from backend.demo.sample_data import get_demo_data
from backend.engine.correlation_engine import correlate_dns_to_aws


def test_demo_data_is_explicitly_synthetic_and_has_an_ip_match():
    dns_results, inventory = get_demo_data()
    assert "synthetic" in inventory["account_id"]
    correlations = correlate_dns_to_aws(dns_results, inventory["resources"])
    assert any(item["status"] == "matched" for item in correlations)


def test_cloud_decommissioning_demo_uses_reserved_synthetic_names_and_addresses():
    from backend.demo.sample_data import get_cloud_decommissioning_demo

    scenario = get_cloud_decommissioning_demo()
    assert scenario["domain"].endswith(".example")
    assert scenario["scenario"]["synthetic"] is True
    assert any(
        host["hostname"].startswith("legacy-api.")
        and host["status"] == "nxdomain"
        for host in scenario["dns"]["results"]
    )
    assert any(
        host["status"] == "partial"
        for host in scenario["dns"]["results"]
    )
