# CAST — Cloud Attack-Surface Decay Tracker

CAST investigates residual infrastructure after application decommissioning by combining passive hostname discovery, DNS observations, external CNAME verification and (when configured) read-only AWS inventory.

> **Important:** CAST produces investigation leads. NXDOMAIN, an external CNAME, an unattached volume, or missing ownership tags do not independently prove abandonment or exploitability.

## Current capabilities

- Passive subdomain discovery from public Certificate Transparency records using crt.sh.
- DNS observations for A, AAAA, CNAME, NS and MX records.
- Partial / NXDOMAIN / resolved DNS status and per-record error reporting.
- External CNAME target verification using A and AAAA lookups.
- Evidence-based findings for potential stale hostnames, external DNS dependencies, incomplete observations and potential dangling CNAME references.
- SQLite scan history.
- Optional read-only AWS inventory for EC2 instances, EBS volumes and S3 bucket configuration.
- Exact DNS A/AAAA to EC2 public/private IP correlation.
- JSON report export from the React dashboard.

## Architecture

```text
React + Vite (CAMERA)
        |
        | HTTP / JSON
        v
Flask API (backend/app.py)
        |
        +-- Certificate Transparency scanner
        +-- DNS scanner
        +-- CNAME target verifier
        +-- Finding engine
        +-- AWS read-only inventory adapter
        +-- DNS / AWS IP correlation
        +-- SQLite scan history
```

## Requirements

- Python 3.11 or later
- Node.js 20.19+ or 22.12+
- npm
- Internet access for crt.sh and public DNS lookups
- Optional: a read-only AWS identity configured on the machine running the Flask backend

## Run locally (Windows PowerShell)

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
python -m backend.app
```

Open a second PowerShell terminal:

```powershell
cd CAMERA
npm install
npm run dev
```

Open the Vite URL printed in the terminal (normally http://localhost:5173).

## Configuration

The backend reads these optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| CAST_DEBUG | false | Flask development debug mode |
| CAST_CORS_ORIGINS | localhost:5173 and 127.0.0.1:5173 | Comma-separated allowed frontend origins |
| CAST_MAX_SCAN_HOSTS | 10 | Maximum hosts assessed per domain scan |
| CAST_MAX_HISTORY_ITEMS | 20 | Reserved history display setting |
| CAST_HISTORY_DB | backend/reports/cast_history.sqlite3 | SQLite history database path |
| AWS_DEFAULT_REGION | ap-south-1 | Default AWS inventory region |
| AWS_PROFILE | default credential chain | Optional local AWS profile name |

The frontend can set `VITE_API_BASE_URL` in `CAMERA/.env.local`, for example:

```env
VITE_API_BASE_URL=http://127.0.0.1:5000
```

Do not put AWS keys or other secrets in any Vite environment variable. Vite variables are exposed to the browser.

## Optional AWS inventory

The AWS feature is optional. The core domain scan works without AWS credentials.

Configure a dedicated read-only AWS identity on the backend host using the AWS SDK default credential chain or a local profile. Grant only the read/list/describe permissions required for STS identity, EC2 instance and volume descriptions, S3 bucket listing, bucket location, public access block and bucket policy status.

Then use **Scan connected AWS account** in the dashboard. The endpoint never accepts access keys or secret keys from the browser. Without valid credentials or permissions, CAST returns an explicit unavailable response and the domain scanner remains usable.

The current correlation is an exact IP match between DNS A/AAAA observations and EC2 public/private addresses in the selected region/account inventory. A non-match does not prove the resource is abandoned; resources in other accounts, regions, CDNs, load balancers or external providers will not appear in that match set.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/health | Backend health check |
| POST | /api/scans/dns | Resolve a supplied hostname list |
| POST | /api/scans/domain | Discover and assess a root domain |
| GET | /api/scans/history | Retrieve recent saved domain scans |
| POST | /api/scans/aws | Collect read-only AWS inventory and correlate supplied DNS observations |

## Tests and build

From the repository root:

```powershell
python -m pytest -q
python -m compileall -q backend
```

Frontend:

```powershell
cd CAMERA
npm ci
npm run lint
npm run build
```

## Detection interpretation

- **Potential stale hostname:** the discovered hostname returned NXDOMAIN during the scan. Confirm the DNS zone and application lifecycle.
- **External DNS dependency:** a CNAME points outside the assessed domain. External hosting/CDNs are normal; this is informational.
- **Potential dangling CNAME:** the external CNAME target returned NXDOMAIN. Provider-side allocation/claimability checks are still required before calling it exploitable.
- **Incomplete DNS observation:** at least one query timed out or failed. Re-run before drawing conclusions.
- **Unattached EBS volume:** a volume is in the available state with no attachments. It may be intentionally retained for backups.
- **Missing ownership metadata:** recognized ownership tags are absent. This is a governance gap, not proof of abandonment.
- **Public S3 bucket policy:** AWS reports the bucket policy as public. Confirm whether the exposure is intentional and review data classification.

## Limitations

- The domain scanner assesses up to 10 hosts by default for a fast demo. Increase `CAST_MAX_SCAN_HOSTS` thoughtfully.
- Certificate Transparency is not a complete inventory of all DNS hostnames.
- DNS observations are point-in-time and can vary with resolver, TTL and network conditions.
- CNAME verification only checks whether A/AAAA lookup succeeds or returns NXDOMAIN; it does not claim resources or prove takeover.
- AWS inventory currently covers EC2 instances, EBS volumes and S3 buckets. It does not yet cover all AWS services, all regions automatically, Route 53 records, ELB, CloudFront or cross-account relationships.
- AWS correlation is exact IP matching only.
- SQLite history is local to the backend host and is not a multi-user shared database.
- This demo has no authentication or role-based access control. Keep the Flask service bound to localhost and do not expose it to the public internet.

## Project status

CAST is a hackathon MVP/prototype. It demonstrates a working discovery-to-findings pipeline and optional cloud inventory correlation. It is not a continuous production monitoring service.
