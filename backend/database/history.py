import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from backend.config import Config


def _db_path(db_path=None):
    return Path(db_path or Config.HISTORY_DB_PATH)


def initialize_history(db_path=None):
    path = _db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        connection.commit()


def save_scan(domain, payload, db_path=None):
    initialize_history(db_path)
    path = _db_path(db_path)
    created_at = datetime.now(timezone.utc).isoformat()
    status = str(payload.get("status", "unknown"))
    with sqlite3.connect(path) as connection:
        cursor = connection.execute(
            "INSERT INTO scans (domain, status, created_at, payload_json) VALUES (?, ?, ?, ?)",
            (domain, status, created_at, json.dumps(payload, default=str)),
        )
        connection.commit()
        return cursor.lastrowid


def list_scans(limit=20, db_path=None):
    initialize_history(db_path)
    path = _db_path(db_path)
    safe_limit = max(1, min(int(limit), 50))
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT id, domain, status, created_at, payload_json FROM scans ORDER BY id DESC LIMIT ?",
            (safe_limit,),
        ).fetchall()

    results = []
    for scan_id, domain, status, created_at, payload_json in rows:
        payload = json.loads(payload_json)
        data = payload.get("data", {})
        dns = data.get("dns", {})
        hosts = dns.get("results", [])
        findings = data.get("findings", [])
        results.append({
            "id": scan_id,
            "domain": domain,
            "status": status,
            "created_at": created_at,
            "hosts_assessed": len(hosts),
            "findings_count": len(findings),
        })
    return results
