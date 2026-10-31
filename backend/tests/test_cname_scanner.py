from backend.scanners import cname_scanner


def test_assess_cname_targets_checks_unique_external_targets(monkeypatch):
    calls = []

    def fake_check(target):
        calls.append(target)
        return {"target": target, "status": "resolves", "evidence": "A resolved"}

    monkeypatch.setattr(cname_scanner, "check_cname_target", fake_check)

    results = [
        {
            "hostname": "a.example.com",
            "records": {"CNAME": ["shared.vendor.net.", "no record"]},
        },
        {
            "hostname": "b.example.com",
            "records": {"CNAME": ["shared.vendor.net."]},
        },
        {
            "hostname": "c.example.com",
            "records": {"CNAME": ["internal.example.com."]},
        },
    ]

    assessments = cname_scanner.assess_cname_targets("example.com", results)

    assert calls == ["shared.vendor.net"]
    assert len(assessments) == 2
    assert assessments[0]["hostname"] == "a.example.com"
    assert assessments[1]["hostname"] == "b.example.com"
