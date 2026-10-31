from flask import Blueprint, jsonify, request

from backend.engine.finding_engine import analyze_dns_results
from backend.scanners.cname_scanner import assess_cname_targets
from backend.scanners.dns_scanner import scan_dns_records
from backend.scanners.subdomain_scanner import (
    discover_subdomains,
    normalize_domain
)

scan_bp = Blueprint("scans", __name__)


@scan_bp.route("/scans/dns", methods=["POST"])
def run_dns_scan():

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "status": "error",
            "message": "Request must contain JSON."
        }), 400

    hostnames = payload.get("hostnames")

    if not isinstance(hostnames, list) or not hostnames:
        return jsonify({
            "status": "error",
            "message": "Provide a non-empty hostnames list."
        }), 400

    if len(hostnames) > 25:
        return jsonify({
            "status": "error",
            "message": "Maximum 25 hostnames per request."
        }), 400

    try:
        result = scan_dns_records(hostnames)

        return jsonify({
            "status": "success",
            "message": "DNS scan completed.",
            "data": result
        }), 200

    except ValueError as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    except Exception:
        return jsonify({
            "status": "error",
            "message": "DNS scan failed."
        }), 500


@scan_bp.route("/scans/domain", methods=["POST"])
def run_domain_scan():

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "status": "error",
            "message": "Request must contain JSON."
        }), 400

    try:
        domain = normalize_domain(payload.get("domain"))

    except ValueError as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    # Step 1: Discover subdomains through Certificate Transparency.
    discovery_error = None

    try:
        discovered = discover_subdomains(domain)
        discovery_status = "success"

    except RuntimeError as error:
        discovered = []
        discovery_status = "unavailable"
        discovery_error = str(error)

    # Step 2: Include root domain and remove duplicates.
    all_hostnames = list(
        dict.fromkeys([domain] + discovered)
    )

    # Limit initial assessment to 10 hostnames.
    selected_hostnames = all_hostnames[:10]

    # Step 3: Resolve DNS records.
    try:
        dns_result = scan_dns_records(selected_hostnames)

    except Exception:
        return jsonify({
            "status": "error",
            "message": "DNS resolution failed."
        }), 500

        # Analyze DNS results
    dns_results = dns_result.get("results", [])

    findings = analyze_dns_results(
        domain,
        dns_results
    )

    # Check external CNAME targets
    cname_assessment_error = None

    try:
        cname_assessments = assess_cname_targets(
            domain,
            dns_results
        )
    except Exception as error:
        cname_assessments = []
        cname_assessment_error = str(error)

    # Identify potential dangling CNAME references
    for assessment in cname_assessments:

        if assessment.get("status") == "nxdomain":

            hostname = assessment["hostname"]
            target = assessment["target"]

            findings.append({
                "id": f"dangling-cname-{hostname}-{target}",
                "type": "potential_dangling_cname",
                "title": "Potential dangling CNAME reference",
                "severity": "medium",
                "confidence": "medium",
                "hostname": hostname,
                "description": (
                    f"{hostname} points to {target}, "
                    "which returned NXDOMAIN during verification."
                ),
                "evidence": [
                    f"CNAME record points to {target}.",
                    f"DNS verification returned NXDOMAIN for {target}."
                ],
                "recommendation": (
                    "Verify external service ownership and whether "
                    "the referenced resource was decommissioned."
                )
            })

    # Step 5: Determine overall scan status.
    final_status = (
        "success"
        if discovery_status == "success"
        else "partial"
    )

    # Step 6: Return complete assessment.
    return jsonify({
        "status": final_status,
        "message": "Domain assessment completed.",
        "data": {
            "domain": domain,

            "discovery": {
                "status": discovery_status,
                "total_discovered": len(discovered),
                "hostnames_selected": len(selected_hostnames),
                "hostnames": selected_hostnames,
                "error": discovery_error
            },

            "dns": dns_result,

            "cname_assessments": cname_assessments,

            "cname_assessment_error": cname_assessment_error,

            "findings": findings
        }
    }), 200