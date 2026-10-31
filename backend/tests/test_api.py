from backend.app import create_app
from backend.routes import scan_routes


def test_domain_route_returns_cname_assessments_and_findings(monkeypatch, tmp_path):
    app = create_app()
    app.config.update(
        TESTING=True,
        HISTORY_DB_PATH=str(tmp_path / "history.sqlite3"),
    )

    monkeypatch.setattr(
        scan_routes,
        "discover_subdomains",
        lambda domain: ["www.example.com"],
    )
    monkeypatch.setattr(
        scan_routes,
        "scan_dns_records",
        lambda hosts: {
            "total_hosts": len(hosts),
            "results": [
                {
                    "hostname": "example.com",
                    "status": "resolved",
                    "records": {"A": ["203.0.113.5"], "CNAME": []},
                    "ttl_seconds": {},
                    "errors": [],
                },
                {
                    "hostname": "www.example.com",
                    "status": "resolved",
                    "records": {"CNAME": ["missing.vendor.invalid."]},
                    "ttl_seconds": {},
                    "errors": [],
                },
            ],
        },
    )
    monkeypatch.setattr(
        scan_routes,
        "assess_cname_targets",
        lambda domain, results: [{
            "hostname": "www.example.com",
            "target": "missing.vendor.invalid",
            "status": "nxdomain",
            "evidence": "NXDOMAIN",
        }],
    )

    client = app.test_client()
    response = client.post("/api/scans/domain", json={"domain": "example.com"})

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["data"]["cname_assessments"]) == 1
    assert any(
        item["type"] == "potential_dangling_cname"
        for item in payload["data"]["findings"]
    )


def test_invalid_domain_is_rejected():
    app = create_app()
    app.config.update(TESTING=True)
    response = app.test_client().post(
        "/api/scans/domain",
        json={"domain": "not a domain"},
    )
    assert response.status_code == 400


def test_aws_route_returns_service_unavailable_without_identity(monkeypatch):
    app = create_app()
    app.config.update(TESTING=True)

    def no_aws(**kwargs):
        raise RuntimeError("No credentials")

    monkeypatch.setattr(scan_routes, "collect_aws_inventory", no_aws)

    response = app.test_client().post("/api/scans/aws", json={"region": "ap-south-1"})
    assert response.status_code == 503
    assert response.get_json()["status"] == "unavailable"


def test_aws_demo_endpoint_is_labelled_synthetic():
    app = create_app()
    app.config.update(TESTING=True)
    response = app.test_client().post("/api/scans/aws/demo", json={})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "demo"
    assert payload["data"]["source"] == "synthetic_demo_data"
    assert "fictional demo fixtures" in payload["data"]["notice"]
    assert any(
        item["status"] == "matched"
        for item in payload["data"]["correlations"]
    )
