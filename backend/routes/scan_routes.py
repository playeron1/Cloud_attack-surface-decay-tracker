
from flask import Blueprint, jsonify, request

from backend.scanners.dns_scanner import scan_dns_records

scan_bp = Blueprint("scans", __name__)


@scan_bp.route("/scans/dns", methods=["POST"])
def run_dns_scan():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "status": "error",
            "message": "Request must contain JSON."
        }), 400

    hostnames = payload.get("hostnames")

    if not isinstance(hostnames, list) or not hostnames:
        return jsonify({
            "status": "error",
            "message": "Provide a non-empty hostnames list."
        }), 400

    if len(hostnames) > 25:
        return jsonify({
            "status": "error",
            "message": "Maximum 25 hostnames per request."
        }), 400

    try:
        result = scan_dns_records(hostnames)

        return jsonify({
            "status": "success",
            "message": "DNS scan completed.",
            "data": result
        }), 200

    except ValueError as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    except Exception:
        return jsonify({
            "status": "error",
            "message": "DNS scan failed."
        }), 500
