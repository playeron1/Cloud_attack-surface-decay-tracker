import ipaddress


def correlate_dns_to_aws(
    dns_results: list[dict],
    aws_resources: list[dict],
) -> list[dict]:
    """Match observed DNS A/AAAA values to EC2 IPs in the supplied inventory."""
    ip_index = {}

    for resource in aws_resources:
        if resource.get("resource_type") != "ec2_instance":
            continue

        for field in ("public_ip", "private_ip"):
            value = resource.get(field)
            if not value:
                continue
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                continue

            ip_index.setdefault(normalized, []).append({
                "resource_id": resource.get("resource_id"),
                "resource_type": "ec2_instance",
                "address_type": field,
                "state": resource.get("state"),
            })

    correlations = []
    for host in dns_results:
        records = host.get("records") or {}
        observed_ips = []

        for record_type in ("A", "AAAA"):
            values = records.get(record_type, [])
            if not isinstance(values, list):
                values = [values]
            for value in values:
                try:
                    observed_ips.append(str(ipaddress.ip_address(str(value).strip())))
                except ValueError:
                    continue

        for address in sorted(set(observed_ips)):
            matches = ip_index.get(address, [])
            correlations.append({
                "hostname": host.get("hostname"),
                "ip_address": address,
                "status": "matched" if matches else "not_in_supplied_inventory",
                "resources": matches,
                "note": (
                    "Exact IP match in supplied AWS EC2 inventory."
                    if matches
                    else "No exact match in this inventory snapshot; this does not mean the IP is abandoned."
                ),
            })

    return correlations
