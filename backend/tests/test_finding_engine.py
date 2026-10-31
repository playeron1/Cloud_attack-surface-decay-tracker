from backend.engine.finding_engine import analyze_aws_inventory, analyze_dns_results


def test_nxdomain_creates_low_confidence_investigation_finding():
    findings = analyze_dns_results(
        "example.com",
        [{"hostname": "old.example.com", "status": "nxdomain", "records": {}}],
    )
    assert len(findings) == 1
    assert findings[0]["type"] == "potential_stale_hostname"
    assert findings[0]["severity"] == "low"
    assert findings[0]["confidence"] == "low"


def test_external_cname_is_classified_as_dependency_not_vulnerability():
    findings = analyze_dns_results(
        "example.com",
        [{
            "hostname": "app.example.com",
            "status": "resolved",
            "records": {"CNAME": ["app.example-cdn.net."]},
        }],
    )
    assert len(findings) == 1
    assert findings[0]["type"] == "external_dns_dependency"
    assert findings[0]["severity"] == "info"
    assert "not vulnerabilities by themselves" in findings[0]["description"]


def test_partial_dns_includes_error_evidence():
    findings = analyze_dns_results(
        "example.com",
        [{
            "hostname": "api.example.com",
            "status": "partial",
            "records": {},
            "errors": [{"record_type": "AAAA", "reason": "DNS query timed out"}],
        }],
    )
    assert findings[0]["type"] == "incomplete_dns_observation"
    assert any("AAAA" in item for item in findings[0]["evidence"])


def test_aws_inventory_flags_unattached_volume_and_public_policy():
    inventory = {
        "resources": [
            {
                "resource_type": "ebs_volume",
                "resource_id": "vol-demo",
                "state": "available",
                "attachment_count": 0,
                "tags": {},
            },
            {
                "resource_type": "s3_bucket",
                "resource_id": "demo-public-bucket",
                "bucket_policy_public": True,
                "tags": {"Owner": "platform"},
            },
        ]
    }
    findings = analyze_aws_inventory(inventory)
    types = {finding["type"] for finding in findings}
    assert "potential_orphaned_storage" in types
    assert "missing_resource_ownership_metadata" in types
    assert "public_bucket_policy" in types
