from backend.engine.correlation_engine import correlate_dns_to_aws


def test_dns_ip_matches_ec2_public_ip():
    dns = [{
        "hostname": "app.example.com",
        "records": {"A": ["203.0.113.10"], "AAAA": []},
    }]
    inventory = [{
        "resource_type": "ec2_instance",
        "resource_id": "i-demo",
        "public_ip": "203.0.113.10",
        "private_ip": "10.0.0.10",
        "state": "running",
    }]

    result = correlate_dns_to_aws(dns, inventory)

    assert len(result) == 1
    assert result[0]["status"] == "matched"
    assert result[0]["resources"][0]["resource_id"] == "i-demo"


def test_unmatched_ip_is_not_described_as_abandoned():
    result = correlate_dns_to_aws(
        [{"hostname": "app.example.com", "records": {"A": ["198.51.100.10"]}}],
        [],
    )
    assert result[0]["status"] == "not_in_supplied_inventory"
    assert "does not mean the IP is abandoned" in result[0]["note"]
