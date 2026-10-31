
import re
import requests

CRT_SH_URL = "https://crt.sh/"

# Validate ordinary ASCII DNS domain names.
LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def normalize_domain(domain):
    """Validate and normalize a domain name."""

    if not isinstance(domain, str):
        raise ValueError("Domain must be a string.")

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain length.")

    labels = domain.split(".")

    if len(labels) < 2 or any(
        not LABEL_PATTERN.fullmatch(label) for label in labels
    ):
        raise ValueError("Enter a valid domain name.")

    return domain


def discover_subdomains(domain):
    """
    Discover hostnames using public Certificate Transparency records.

    This function performs passive discovery only.
    """

    domain = normalize_domain(domain)

    params = {
        "q": f"%.{domain}",
        "output": "json"
    }

    headers = {
        "User-Agent": "CAST-Scanner/0.1"
    }

    try:
        response = requests.get(
            CRT_SH_URL,
            params=params,
            headers=headers,
            timeout=(5,45)
        )

        if response.status_code == 429:
            raise RuntimeError("CT service rate limit reached.")

        response.raise_for_status()

        records = response.json()

    except requests.RequestException as error:
        raise RuntimeError(
            f"Certificate Transparency request failed: {error}"
        ) from error

    except ValueError as error:
        raise RuntimeError(
            "Could not decode CT service response."
        ) from error

    discovered = set()

    for record in records:
        names = [
            record.get("name_value", ""),
            record.get("common_name", "")
        ]

        for value in names:
            for hostname in value.splitlines():

                hostname = hostname.strip().lower().rstrip(".")

                # Convert wildcard entries into ordinary hostnames.
                if hostname.startswith("*."):
                    hostname = hostname[2:]

                # Keep only the requested domain and its subdomains.
                if (
                    hostname == domain
                    or hostname.endswith("." + domain)
                ):
                    discovered.add(hostname)

    return sorted(discovered)
