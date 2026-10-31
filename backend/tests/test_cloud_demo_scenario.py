from backend.app import create_app


def test_cloud_demo_contains_cloud_lifecycle_evidence():
    app = create_app()
    app.config.update(TESTING=True)
    response = app.test_client().post("/api/scans/demo", json={})

    assert response.status_code == 200
    payload = response.get_json()
    data = payload["data"]

    assert data["domain"] == "northstar-retail.example"
    assert data["scenario"]["synthetic"] is True
    assert any(host["status"] == "nxdomain" for host in data["dns"]["results"])
    assert any(host["status"] == "partial" for host in data["dns"]["results"])
    assert any(
        item["status"] == "nxdomain"
        for item in data["cname_assessments"]
    )
    assert any(
        finding["type"] == "potential_orphaned_storage"
        for finding in data["aws"]["findings"]
    )
    assert any(
        finding["type"] == "public_bucket_policy"
        for finding in data["aws"]["findings"]
    )
    assert any(
        item["status"] == "matched"
        for item in data["aws"]["correlations"]
    )
