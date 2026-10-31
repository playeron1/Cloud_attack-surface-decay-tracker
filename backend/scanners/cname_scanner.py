from backend.scanners.dns_scanner import normalize_hostname

import dns.resolver
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers


def check_cname_target(target, timeout=2.0):
    """Check whether an external CNAME target resolves."""

    try:
        target = normalize_hostname(target)
    except ValueError:
        return {
            "target": str(target),
            "status": "invalid",
            "evidence": "Invalid DNS target."
        }

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    errors = []

    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(
                target,
                record_type,
                lifetime=timeout,
                search=False
            )

            if answer:
                return {
                    "target": target,
                    "status": "resolves",
                    "record_type": record_type,
                    "evidence": f"{record_type} records successfully resolved."
                }

        except NXDOMAIN:
            return {
                "target": target,
                "status": "nxdomain",
                "evidence": "DNS resolver returned NXDOMAIN."
            }

        except NoAnswer:
            continue

        except (Timeout, NoNameservers) as error:
            errors.append(str(error))

    if errors:
        return {
            "target": target,
            "status": "inconclusive",
            "evidence": "DNS verification could not be completed.",
            "errors": errors
        }

    return {
        "target": target,
        "status": "no_address_records",
        "evidence": "No A or AAAA records were returned."
    }


def assess_cname_targets(domain, dns_results):
    """Extract and assess unique external CNAME targets."""

    root_domain = normalize_hostname(domain)
    assessments = []
    checked_targets = {}

    for host in dns_results:
        hostname = host.get("hostname", "")
        records = host.get("records", {})

        if not isinstance(records, dict):
            continue

        cname_values = records.get("CNAME", [])

        if not isinstance(cname_values, list):
            cname_values = [cname_values]

        for raw_target in cname_values:
            if not isinstance(raw_target, str):
                continue

            target = raw_target.strip().lower().rstrip(".")

            if target in {"", "no record", "none", "-"}:
                continue

            try:
                target = normalize_hostname(target)
            except ValueError:
                continue

            if (
                target == root_domain
                or target.endswith("." + root_domain)
            ):
                continue

            if target not in checked_targets:
                checked_targets[target] = check_cname_target(target)

            assessments.append({
                "hostname": hostname,
                **checked_targets[target]
            })

    return assessments
