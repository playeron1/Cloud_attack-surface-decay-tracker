import logging
import re

from flask import Blueprint, current_app, jsonify, request

from backend.engine.correlation_engine import correlate_dns_to_aws
from backend.engine.finding_engine import analyze_aws_inventory, analyze_dns_results
from backend.database.history import list_scans, save_scan
from backend.demo.sample_data import get_cloud_decommissioning_demo, get_demo_data
from backend.scanners.aws_scanner import collect_aws_inventory
from backend.scanners.cname_scanner import assess_cname_targets
from backend.scanners.dns_scanner import scan_dns_records
from backend.scanners.subdomain_scanner import discover_subdomains, normalize_domain

logger = logging.getLogger(__name__)
scan_bp = Blueprint("scans", __name__)


@scan_bp.route("/scans/dns", methods=["POST"])
def run_dns_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request must contain JSON."}), 400

    hostnames = payload.get("hostnames")
    if not isinstance(hostnames, list) or not hostnames:
        return jsonify({"status": "error", "message": "Provide a non-empty hostnames list."}), 400
    if len(hostnames) > 25:
        return jsonify({"status": "error", "message": "Maximum 25 hostnames per request."}), 400

    try:
        result = scan_dns_records(hostnames)
        return jsonify({"status": "success", "message": "DNS scan completed.", "data": result}), 200
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    except Exception:
        logger.exception("DNS scan failed")
        return jsonify({"status": "error", "message": "DNS scan failed."}), 500


@scan_bp.route("/scans/domain", methods=["POST"])
def run_domain_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request must contain JSON."}), 400

    try:
        domain = normalize_domain(payload.get("domain"))
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400

    discovery_error = None
    try:
        discovered = discover_subdomains(domain)
        discovery_status = "success"
    except RuntimeError as error:
        discovered = []
        discovery_status = "unavailable"
        discovery_error = str(error)
    except Exception:
        logger.exception("Unexpected CT discovery error")
        discovered = []
        discovery_status = "unavailable"
        discovery_error = "Certificate Transparency discovery failed."

    all_hostnames = list(dict.fromkeys([domain] + discovered))
    max_hosts = current_app.config["MAX_SCAN_HOSTS"]
    selected_hostnames = all_hostnames[:max_hosts]

    try:
        dns_result = scan_dns_records(selected_hostnames)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    except Exception:
        logger.exception("DNS resolution failed")
        return jsonify({"status": "error", "message": "DNS resolution failed."}), 500

    dns_results = dns_result.get("results", [])
    findings = analyze_dns_results(domain, dns_results)

    cname_assessments = []
    cname_assessment_error = None
    try:
        cname_assessments = assess_cname_targets(domain, dns_results)
    except Exception:
        logger.exception("CNAME verification failed")
        cname_assessment_error = "Some external CNAME targets could not be verified."

    seen_dangling = set()
    for assessment in cname_assessments:
        if assessment.get("status") != "nxdomain":
            continue

        hostname = assessment.get("hostname", "")
        target = assessment.get("target", "")
        key = (hostname, target)
        if key in seen_dangling:
            continue
        seen_dangling.add(key)

        findings.append({
            "id": f"dangling-cname-{hostname}-{target}",
            "type": "potential_dangling_cname",
            "title": "Potential dangling CNAME reference",
            "severity": "medium",
            "confidence": "medium",
            "hostname": hostname,
            "target": target,
            "description": (
                f"{hostname} points to {target}, which returned NXDOMAIN "
                "during this observation. This does not prove that a third-party "
                "service can be claimed."
            ),
            "evidence": [
                f"CNAME record points to {target}.",
                "DNS verification returned NXDOMAIN for the target.",
            ],
            "recommendation": (
                "Verify provider-side resource allocation, service ownership "
                "and the application's decommissioning record before treating "
                "this as an exploitable issue."
            ),
        })

    statuses = {host.get("status") for host in dns_results}
    final_status = (
        "partial"
        if discovery_status != "success"
        or "partial" in statuses
        or cname_assessment_error
        else "success"
    )

    response_data = {
        "domain": domain,
        "discovery": {
            "status": discovery_status,
            "total_discovered": len(discovered),
            "hostnames_selected": len(selected_hostnames),
            "hostnames": selected_hostnames,
            "error": discovery_error,
        },
        "dns": dns_result,
        "cname_assessments": cname_assessments,
        "cname_assessment_error": cname_assessment_error,
        "findings": findings,
    }

    history_saved = True
    try:
        save_scan(
            domain,
            {"status": final_status, "data": response_data},
            db_path=current_app.config["HISTORY_DB_PATH"],
        )
    except Exception:
        logger.exception("Could not save scan history")
        history_saved = False

    return jsonify({
        "status": final_status,
        "message": "Domain assessment completed.",
        "history_saved": history_saved,
        "data": response_data,
    }), 200


@scan_bp.route("/scans/history", methods=["GET"])
def get_scan_history():
    try:
        limit = int(request.args.get("limit", 10))
        return jsonify({
            "status": "success",
            "data": list_scans(
                limit=min(limit, current_app.config["MAX_HISTORY_ITEMS"]),
                db_path=current_app.config["HISTORY_DB_PATH"],
            ),
        }), 200
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Limit must be an integer."}), 400
    except Exception:
        logger.exception("Could not retrieve scan history")
        return jsonify({"status": "error", "message": "Scan history is unavailable."}), 500


@scan_bp.route("/scans/aws", methods=["POST"])
def run_aws_scan():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request must contain JSON."}), 400

    region = payload.get("region") or current_app.config["AWS_DEFAULT_REGION"]
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region):
        return jsonify({"status": "error", "message": "Provide a valid AWS region."}), 400

    dns_results = payload.get("dns_results", [])
    if not isinstance(dns_results, list) or len(dns_results) > 250:
        return jsonify({"status": "error", "message": "DNS correlation input must be a list of at most 250 hosts."}), 400

    try:
        inventory = collect_aws_inventory(
            region_name=region,
            profile_name=current_app.config["AWS_PROFILE_NAME"],
        )
    except RuntimeError:
        logger.exception("AWS inventory collection failed")
        return jsonify({
            "status": "unavailable",
            "message": (
                "AWS inventory is unavailable. Configure a read-only AWS "
                "identity and the required permissions, then retry."
            ),
            "data": {"region": region},
        }), 503
    except Exception:
        logger.exception("Unexpected AWS inventory error")
        return jsonify({
            "status": "unavailable",
            "message": "AWS inventory could not be collected.",
            "data": {"region": region},
        }), 503

    aws_findings = analyze_aws_inventory(inventory)
    correlations = correlate_dns_to_aws(
        dns_results,
        inventory.get("resources", []),
    )

    return jsonify({
        "status": "success",
        "message": "AWS inventory collected.",
        "data": {
            "inventory": inventory,
            "findings": aws_findings,
            "correlations": correlations,
        },
    }), 200


@scan_bp.route("/scans/aws/demo", methods=["POST"])
def run_aws_demo():
    """Return clearly labelled synthetic fixtures for a judge/demo walkthrough."""
    dns_results, inventory = get_demo_data()
    findings = analyze_aws_inventory(inventory)
    correlations = correlate_dns_to_aws(
        dns_results,
        inventory.get("resources", []),
    )

<<<<<<< HEAD
            "cname_assessments": cname_assessments,

            "cname_assessment_error": cname_assessment_error,

            "findings": findings
        }
    }), 200
=======
    return jsonify({
        "status": "demo",
        "message": "Synthetic AWS sample loaded. This is not live account data.",
        "data": {
            "source": "synthetic_demo_data",
            "notice": "All account IDs, resources and DNS observations in this view are fictional demo fixtures.",
            "dns_results": dns_results,
            "inventory": inventory,
            "findings": findings,
            "correlations": correlations,
        },
    }), 200


@scan_bp.route("/scans/demo", methods=["POST"])
def run_cloud_decommissioning_demo():
    """Return one coherent fictional cloud-decommissioning assessment."""
    scenario = get_cloud_decommissioning_demo()
    domain = scenario["domain"]
    dns_results = scenario["dns"]["results"]

    findings = analyze_dns_results(domain, dns_results)

    for assessment in scenario["cname_assessments"]:
        if assessment.get("status") != "nxdomain":
            continue
        hostname = assessment["hostname"]
        target = assessment["target"]
        findings.append({
            "id": f"demo-dangling-cname-{hostname}",
            "type": "potential_dangling_cname",
            "title": "Potential dangling CNAME reference",
            "severity": "medium",
            "confidence": "medium",
            "hostname": hostname,
            "target": target,
            "description": (
                f"{hostname} points to {target}, which is marked NXDOMAIN "
                "in this synthetic scenario. Provider-side claimability is "
                "not tested or implied."
            ),
            "evidence": [
                f"Synthetic CNAME target: {target}.",
                "Synthetic fixture marks target as NXDOMAIN.",
            ],
            "recommendation": (
                "In a real environment, verify provider-side allocation, "
                "resource ownership and change/decommission records."
            ),
        })

    inventory = scenario.pop("inventory")
    aws_findings = analyze_aws_inventory(inventory)
    correlations = correlate_dns_to_aws(dns_results, inventory.get("resources", []))

    scenario["findings"] = findings
    scenario["aws"] = {
        "source": "synthetic_demo_data",
        "notice": scenario["scenario"]["notice"],
        "inventory": inventory,
        "findings": aws_findings,
        "correlations": correlations,
    }

    return jsonify({
        "status": "demo",
        "message": "Synthetic cloud decommissioning scenario loaded. No live domain or AWS account was scanned.",
        "data": scenario,
    }), 200
>>>>>>> 271155c94c63bb5be125102ae2a8531ed300f3d0
