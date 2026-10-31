from typing import Any


def _normalize_domain(domain: str) -> str:
    return domain.lower().strip().rstrip(".")


def _get_records(host: dict[str, Any]) -> list[dict[str, Any]]:
    records = host.get("records", [])

    if isinstance(records, list):
        return records

    flattened = []
    if isinstance(records, dict):
        for record_type, values in records.items():
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if isinstance(value, dict):
                    flattened.append({"type": record_type, **value})
                else:
                    flattened.append({"type": record_type, "value": value})
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

        if status == "nxdomain":
            findings.append({
                "id": f"stale-host-{hostname}",
                "type": "potential_stale_hostname",
                "title": "Potential stale hostname",
                "severity": "low",
                "confidence": "low",
                "hostname": hostname,
                "description": (
                    "This hostname was discovered but currently returns NXDOMAIN. "
                    "This alone does not prove a decommissioned application."
                ),
                "evidence": [
                    "Hostname discovered during domain assessment.",
                    "DNS lookup returned NXDOMAIN.",
                ],
                "recommendation": (
                    "Verify the authoritative DNS zone, application lifecycle "
                    "and cloud resource inventory before treating this as abandoned."
                ),
            })

        if status == "partial":
            errors = host.get("errors", [])
            evidence = ["One or more DNS observations did not complete."]
            for item in errors:
                if isinstance(item, dict):
                    evidence.append(
                        f'{item.get("record_type", "DNS")}: {item.get("reason", "Unknown error")}'
                    )
            findings.append({
                "id": f"partial-dns-{hostname}",
                "type": "incomplete_dns_observation",
                "title": "Incomplete DNS observation",
                "severity": "info",
                "confidence": "high",
                "hostname": hostname,
                "description": "Some DNS record lookups did not complete successfully.",
                "evidence": evidence,
                "recommendation": "Repeat the DNS assessment before making a conclusion.",
            })

        for record in _get_records(host):
            record_type = str(
                record.get("type", record.get("record_type", ""))
            ).upper()
            target = str(
                record.get("value", record.get("data", ""))
            ).strip().lower().rstrip(".")

            if record_type != "CNAME" or not target:
                continue
            if target in {"no record", "none", "-"}:
                continue

            is_internal = (
                target == root_domain
                or target.endswith("." + root_domain)
            )
            if not is_internal:
                findings.append({
                    "id": f"external-cname-{hostname}-{target}",
                    "type": "external_dns_dependency",
                    "title": "External DNS dependency",
                    "severity": "info",
                    "confidence": "high",
                    "hostname": hostname,
                    "target": target,
                    "description": (
                        f"This hostname points to the external DNS target {target}. "
                        "External hosting and CDN dependencies are common and are "
                        "not vulnerabilities by themselves."
                    ),
                    "evidence": [f"CNAME record points to {target}."],
                    "recommendation": (
                        "Verify that the external service is still owned, active "
                        "and intentionally referenced."
                    ),
                })

    return findings


def analyze_aws_inventory(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate cautious inventory findings; these are indicators, not proof of abandonment."""
    findings = []

    for resource in inventory.get("resources", []):
        resource_type = resource.get("resource_type", "unknown")
        resource_id = resource.get("resource_id", "unknown")
        tags = resource.get("tags") or {}
        tag_keys = {str(key).strip().lower() for key in tags}

        if not ({"owner", "owneremail", "project", "application", "service"} & tag_keys):
            findings.append({
                "id": f"ownership-metadata-{resource_type}-{resource_id}",
                "type": "missing_resource_ownership_metadata",
                "title": "Missing ownership metadata",
                "severity": "info",
                "confidence": "high",
                "hostname": resource_id,
                "description": (
                    f"{resource_type} {resource_id} has no recognized Owner, "
                    "Project, Application or Service tag."
                ),
                "evidence": ["No recognized ownership tag was found in the resource tags."],
                "recommendation": "Confirm the responsible team and add ownership and lifecycle tags.",
            })

        if (
            resource_type == "ebs_volume"
            and resource.get("attachment_count", 0) == 0
            and resource.get("state") == "available"
        ):
            findings.append({
                "id": f"unattached-ebs-{resource_id}",
                "type": "potential_orphaned_storage",
                "title": "Unattached EBS volume",
                "severity": "low",
                "confidence": "medium",
                "hostname": resource_id,
                "description": (
                    f"EBS volume {resource_id} is available and has no current attachments. "
                    "It may be retained intentionally for backup or recovery."
                ),
                "evidence": [
                    "Volume state is available.",
                    "Attachment count is zero.",
                ],
                "recommendation": "Check snapshots, backup policy, owner and retention requirements before deleting.",
            })

        if (
            resource_type == "s3_bucket"
            and resource.get("public_access_block_status") == "not_configured"
        ):
            findings.append({
                "id": f"s3-public-access-block-{resource_id}",
                "type": "s3_public_access_block_not_configured",
                "title": "S3 bucket-level public access block not configured",
                "severity": "info",
                "confidence": "high",
                "hostname": resource_id,
                "description": (
                    f"S3 bucket {resource_id} has no bucket-level public access block. "
                    "An account-level block may still apply."
                ),
                "evidence": ["GetPublicAccessBlock returned NoSuchPublicAccessBlockConfiguration."],
                "recommendation": (
                    "Review account-level and bucket-level public access controls, "
                    "then apply the organization's intended baseline."
                ),
            })

        if (
            resource_type == "s3_bucket"
            and resource.get("bucket_policy_public") is True
        ):
            findings.append({
                "id": f"public-s3-policy-{resource_id}",
                "type": "public_bucket_policy",
                "title": "S3 bucket policy permits public access",
                "severity": "high",
                "confidence": "high",
                "hostname": resource_id,
                "description": (
                    f"S3 bucket {resource_id} is reported as public by the bucket policy status API."
                ),
                "evidence": ["GetBucketPolicyStatus returned IsPublic=true."],
                "recommendation": "Verify whether public access is intentional and review the bucket policy and data classification.",
            })

    return findings
