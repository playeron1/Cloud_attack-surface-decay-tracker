
import re

import dns.resolver
from dns.exception import Timeout
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers


RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX"]

LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def normalize_hostname(hostname):
    """Validate and normalize a DNS hostname."""

    if not isinstance(hostname, str):
        raise ValueError("Hostname must be a string.")

    hostname = hostname.strip().lower().rstrip(".")

    if not hostname or len(hostname) > 253:
        raise ValueError("Invalid hostname length.")

    labels = hostname.split(".")

    if any(
        not LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        raise ValueError(f"Invalid hostname: {hostname}")

    return hostname


def resolve_dns_records(hostname, timeout=3.0):
    """
    Resolve selected DNS records for one hostname.

    Returns DNS observations without modifying any records.
    """

    hostname = normalize_hostname(hostname)

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout

    result = {
        "hostname": hostname,
        "status": "resolved",
        "records": {},
        "ttl_seconds": {},
        "errors": []
    }

    for record_type in RECORD_TYPES:

        try:
            answer = resolver.resolve(
                hostname,
                record_type,
                lifetime=timeout,
                search=False
            )

            result["records"][record_type] = [
                record.to_text() for record in answer
            ]

            if answer.rrset:
                result["ttl_seconds"][record_type] = (
                    answer.rrset.ttl
                )

        except NoAnswer:
            # The hostname may exist without this record type.
            result["records"][record_type] = []

        except NXDOMAIN:
            result["status"] = "nxdomain"

            result["records"][record_type] = []

            break

        except Timeout:
            result["status"] = "partial"

            result["records"][record_type] = []

            result["errors"].append({
                "record_type": record_type,
                "reason": "DNS query timed out"
            })

        except NoNameservers:
            result["status"] = "partial"

            result["records"][record_type] = []

            result["errors"].append({
                "record_type": record_type,
                "reason": "No DNS nameserver responded"
            })

    return result


def scan_dns_records(hostnames, timeout=3.0):
    """Resolve DNS records for multiple unique hostnames."""

    unique_hostnames = list(
        dict.fromkeys(
            normalize_hostname(hostname)
            for hostname in hostnames
        )
    )

    results = []

    for hostname in unique_hostnames:
        results.append(
            resolve_dns_records(hostname, timeout)
        )

    return {
        "total_hosts": len(unique_hostnames),
        "results": results
    }
