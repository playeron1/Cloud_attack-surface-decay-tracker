from backend.database.history import list_scans, save_scan


def test_scan_history_round_trip(tmp_path):
    db_path = tmp_path / "history.sqlite3"
    payload = {
        "status": "success",
        "data": {
            "dns": {"results": [{"hostname": "example.com"}]},
            "findings": [{"type": "sample"}],
        },
    }

    save_scan("example.com", payload, db_path=db_path)
    scans = list_scans(limit=5, db_path=db_path)

    assert len(scans) == 1
    assert scans[0]["domain"] == "example.com"
    assert scans[0]["hosts_assessed"] == 1
    assert scans[0]["findings_count"] == 1
