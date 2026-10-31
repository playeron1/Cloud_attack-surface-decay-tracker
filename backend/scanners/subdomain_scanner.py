
import re
import time
import requests


CRT_SH_URL = "https://crt.sh/"

LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def normalize_domain(domain):
    """Validate and normalize a root domain."""

    if not isinstance(domain, str):
        raise ValueError("Domain must be a string.")

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain length.")

    labels = domain.split(".")

    if len(labels) < 2 or any(
        not LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        raise ValueError("Enter a valid domain name.")

    return domain


def discover_subdomains(domain):
    """Discover hostnames from public Certificate Transparency data."""

    domain = normalize_domain(domain)

    params = {
        "q": f"%.{domain}",
        "output": "json"
    }

    headers = {
        "User-Agent": "CAST-Scanner/0.1"
    }

    records = None
    last_error = None

    # Two attempts: initial request plus one retry.
    for attempt in range(2):
        try:
            response = requests.get(
                CRT_SH_URL,
                params=params,
                headers=headers,
                timeout=(5, 30)
            )

            if response.status_code in (429, 500, 502, 503, 504):
                if attempt == 0:
                    time.sleep(2)
                    continue

            response.raise_for_status()
            records = response.json()

            if not isinstance(records, list):
                raise RuntimeError(
                    "Unexpected Certificate Transparency response."
                )

            break

        except (requests.Timeout, requests.ConnectionError) as error:
            last_error = error

            if attempt == 0:
                time.sleep(2)
                continue

            raise RuntimeError(
                f"CT service unavailable after retry: {error}"
            ) from error

        except requests.HTTPError as error:
            raise RuntimeError(
                f"CT service returned HTTP error: {error}"
            ) from error

        except ValueError as error:
            raise RuntimeError(
                "Could not decode CT service response."
            ) from error

    if records is None:
        raise RuntimeError(
            f"CT discovery failed: {last_error}"
        )

    discovered = set()

    for record in records:
        if not isinstance(record, dict):
            continue

        names = [
            record.get("name_value", ""),
            record.get("common_name", "")
        ]

        for value in names:
            if not isinstance(value, str):
                continue

            for hostname in value.splitlines():
                hostname = hostname.strip().lower().rstrip(".")

                if hostname.startswith("*."):
                    hostname = hostname[2:]

                if (
                    hostname == domain
                    or hostname.endswith("." + domain)
                ):
                    discovered.add(hostname)

    return sorted(discovered)
