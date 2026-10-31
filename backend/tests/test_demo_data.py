from backend.demo.sample_data import get_demo_data
from backend.engine.correlation_engine import correlate_dns_to_aws


def test_demo_data_is_explicitly_synthetic_and_has_an_ip_match():
    dns_results, inventory = get_demo_data()
    assert "synthetic" in inventory["account_id"]
    correlations = correlate_dns_to_aws(dns_results, inventory["resources"])
    assert any(item["status"] == "matched" for item in correlations)
