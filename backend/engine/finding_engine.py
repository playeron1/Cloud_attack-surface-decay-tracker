from typing import Any


def _normalize_domain(domain: str) -> str:
    return domain.lower().strip().rstrip(".")


def _get_records(host: dict[str, Any]) -> list[dict[str, Any]]:
    records = host.get("records", [])

    if isinstance(records, list):
        return records

    # Also support records grouped by DNS record type.
    flattened = []

    if isinstance(records, dict):
        for record_type, values in records.items():
            if not isinstance(values, list):
                values = [values]

            for value in values:
                if isinstance(value, dict):
                    flattened.append({
                        "type": record_type,
                        **value,
                    })
                else:
                    flattened.append({
                        "type": record_type,
                        "value": value,
                    })

    return flattened


def analyze_dns_results(
    domain: str,
    dns_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    root_domain = _normalize_domain(domain)
    findings = []

    for host in dns_results:
        hostname = _normalize_domain(
            host.get("hostname") or host.get("host") or ""
        )

        if not hostname:
            continue

        status = str(host.get("status", "")).lower()

        # Finding 1: Potential stale hostname
        if status == "nxdomain":
            findings.append({
                "id": f"stale-host-{hostname}",
                "type": "potential_stale_hostname",
                "title": "Potential stale hostname",
                "severity": "low",
                "confidence": "low",
                "hostname": hostname,
                "description": (
                    "This hostname was discovered but currently "
                    "returns NXDOMAIN."
                ),
                "evidence": [
                    "Hostname discovered during domain assessment.",
                    "DNS lookup returned NXDOMAIN."
                ],
                "recommendation": (
                    "Verify whether the application was decommissioned "
                    "and check the authoritative DNS zone and resource inventory."
                )
            })

        # Finding 2: Incomplete DNS observation
        if status == "partial":
            findings.append({
                "id": f"partial-dns-{hostname}",
                "type": "incomplete_dns_observation",
                "title": "Incomplete DNS observation",
                "severity": "info",
                "confidence": "high",
                "hostname": hostname,
                "description": (
                    "Some DNS record lookups did not complete successfully."
                ),
                "evidence": [
                    "DNS scanner returned a partial result."
                ],
                "recommendation": (
                    "Repeat the DNS assessment before making a conclusion."
                )
            })

        # Finding 3: External CNAME dependency
        for record in _get_records(host):
            record_type = str(
                record.get("type", record.get("record_type", ""))
            ).upper()

            target = str(
                record.get("value", record.get("data", ""))
            ).strip().lower().rstrip(".")

            if (
                record_type == "CNAME"
                and target
                and target not in {"no record", "none", "-"}
            ):
                is_internal = (
                    target == root_domain
                    or target.endswith("." + root_domain)
                )

                if not is_internal:
                    findings.append({
                        "id": f"external-cname-{hostname}",
                        "type": "external_dns_dependency",
                        "title": "External DNS dependency",
                        "severity": "info",
                        "confidence": "high",
                        "hostname": hostname,
                        "description": (
                            f"This hostname points to the external "
                            f"DNS target {target}."
                        ),
                        "evidence": [
                            f"CNAME record points to {target}."
                        ],
                        "recommendation": (
                            "Verify that the external service is still "
                            "owned, active and intentionally referenced."
                        )
                    })

    return findings