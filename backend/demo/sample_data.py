from copy import deepcopy


DEMO_DNS_RESULTS = [
    {
        "hostname": "legacy-app.demo.cast.invalid",
        "status": "resolved",
        "records": {"A": ["203.0.113.10"], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
        "ttl_seconds": {"A": 60},
        "errors": [],
    },
    {
        "hostname": "api.demo.cast.invalid",
        "status": "resolved",
        "records": {"A": ["198.51.100.20"], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
        "ttl_seconds": {"A": 60},
        "errors": [],
    },
]

DEMO_AWS_INVENTORY = {
    "provider": "aws-demo",
    "account_id": "000000000000 (synthetic)",
    "region": "ap-south-1",
    "total_resources": 4,
    "resources": [
        {
            "provider": "aws-demo",
            "resource_type": "ec2_instance",
            "resource_id": "i-cast-demo-001",
            "state": "running",
            "instance_type": "t3.small",
            "launch_time": "2026-01-15T10:00:00+00:00",
            "public_ip": "203.0.113.10",
            "private_ip": "10.0.1.12",
            "vpc_id": "vpc-demo-001",
            "tags": {
                "Owner": "Demo Platform",
                "Project": "CAST Demo",
                "Environment": "demo",
            },
        },
        {
            "provider": "aws-demo",
            "resource_type": "ec2_instance",
            "resource_id": "i-cast-demo-002",
            "state": "stopped",
            "instance_type": "t3.micro",
            "launch_time": "2025-12-01T10:00:00+00:00",
            "public_ip": None,
            "private_ip": "10.0.2.25",
            "vpc_id": "vpc-demo-001",
            "tags": {},
        },
        {
            "provider": "aws-demo",
            "resource_type": "ebs_volume",
            "resource_id": "vol-cast-demo-001",
            "state": "available",
            "size_gb": 20,
            "encrypted": False,
            "attachment_count": 0,
            "create_time": "2025-11-10T10:00:00+00:00",
            "tags": {},
        },
        {
            "provider": "aws-demo",
            "resource_type": "s3_bucket",
            "resource_id": "cast-demo-public-bucket",
            "creation_date": "2025-10-01T10:00:00+00:00",
            "region": "ap-south-1",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "public_access_block_status": "configured",
            "bucket_policy_public": True,
            "tags": {
                "Owner": "Demo Platform",
                "Project": "CAST Demo",
            },
        },
    ],
}


def get_demo_data():
    """Return copies so a test or request cannot mutate the shared fixture."""
    return deepcopy(DEMO_DNS_RESULTS), deepcopy(DEMO_AWS_INVENTORY)


def get_cloud_decommissioning_demo():
    """Return a coherent, fictional retired-application cloud environment."""
    dns_results = [
        {
            "hostname": "northstar-retail.example",
            "status": "resolved",
            "records": {"A": ["203.0.113.10"], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
            "ttl_seconds": {"A": 300},
            "errors": [],
        },
        {
            "hostname": "portal.northstar-retail.example",
            "status": "resolved",
            "records": {"A": ["203.0.113.10"], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
            "ttl_seconds": {"A": 60},
            "errors": [],
        },
        {
            "hostname": "api.northstar-retail.example",
            "status": "resolved",
            "records": {"A": ["198.51.100.20"], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
            "ttl_seconds": {"A": 60},
            "errors": [],
        },
        {
            "hostname": "legacy-api.northstar-retail.example",
            "status": "nxdomain",
            "records": {"A": [], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
            "ttl_seconds": {},
            "errors": [],
        },
        {
            "hostname": "assets.northstar-retail.example",
            "status": "resolved",
            "records": {
                "A": [], "AAAA": [],
                "CNAME": ["retired-assets.vendor.invalid."],
                "NS": [], "MX": [],
            },
            "ttl_seconds": {"CNAME": 60},
            "errors": [],
        },
        {
            "hostname": "static.northstar-retail.example",
            "status": "resolved",
            "records": {
                "A": [], "AAAA": [],
                "CNAME": ["cdn.vendor.example."],
                "NS": [], "MX": [],
            },
            "ttl_seconds": {"CNAME": 300},
            "errors": [],
        },
        {
            "hostname": "admin.northstar-retail.example",
            "status": "partial",
            "records": {"A": ["198.51.100.30"], "AAAA": [], "CNAME": [], "NS": [], "MX": []},
            "ttl_seconds": {"A": 60},
            "errors": [{"record_type": "AAAA", "reason": "Synthetic timeout fixture"}],
        },
    ]

    inventory = {
        "provider": "aws-demo",
        "account_id": "000000000000 (synthetic)",
        "region": "ap-south-1",
        "total_resources": 4,
        "resources": [
            {
                "provider": "aws-demo",
                "resource_type": "ec2_instance",
                "resource_id": "i-northstar-web-01",
                "state": "running",
                "instance_type": "t3.small",
                "public_ip": "203.0.113.10",
                "private_ip": "10.0.1.10",
                "vpc_id": "vpc-northstar-demo",
                "tags": {"Owner": "Northstar Platform", "Project": "Storefront"},
            },
            {
                "provider": "aws-demo",
                "resource_type": "ec2_instance",
                "resource_id": "i-northstar-old-api",
                "state": "stopped",
                "instance_type": "t3.micro",
                "public_ip": None,
                "private_ip": "10.0.2.25",
                "vpc_id": "vpc-northstar-demo",
                "tags": {},
            },
            {
                "provider": "aws-demo",
                "resource_type": "ebs_volume",
                "resource_id": "vol-northstar-unattached",
                "state": "available",
                "size_gb": 40,
                "encrypted": False,
                "attachment_count": 0,
                "tags": {},
            },
            {
                "provider": "aws-demo",
                "resource_type": "s3_bucket",
                "resource_id": "northstar-legacy-assets-demo",
                "region": "ap-south-1",
                "public_access_block_status": "configured",
                "bucket_policy_public": True,
                "tags": {"Owner": "Northstar Platform", "Project": "Storefront"},
            },
        ],
    }

    cname_assessments = [
        {
            "hostname": "assets.northstar-retail.example",
            "target": "retired-assets.vendor.invalid",
            "status": "nxdomain",
            "evidence": "Synthetic fixture: target is designated NXDOMAIN for this demo.",
        },
        {
            "hostname": "static.northstar-retail.example",
            "target": "cdn.vendor.example",
            "status": "resolves",
            "record_type": "A",
            "evidence": "Synthetic fixture: CDN target is designated as resolving.",
        },
    ]

    return {
        "domain": "northstar-retail.example",
        "scenario": {
            "name": "Northstar Retail — retired online storefront",
            "description": (
                "A fictional retail application was decommissioned, but DNS "
                "references and cloud resources remain in the inventory."
            ),
            "lifecycle_event": "Storefront retirement review",
            "synthetic": True,
            "notice": (
                "All domains, IP addresses, AWS account identifiers and resources "
                "in this scenario are fictional. Reserved documentation IP ranges "
                "are used; no real customer or cloud account is being scanned."
            ),
        },
        "discovery": {
            "status": "synthetic",
            "source": "synthetic_demo_data",
            "total_discovered": len(dns_results) - 1,
            "hostnames_selected": len(dns_results),
            "hostnames": [item["hostname"] for item in dns_results],
            "error": None,
        },
        "dns": {
            "total_hosts": len(dns_results),
            "results": dns_results,
        },
        "cname_assessments": cname_assessments,
        "cname_assessment_error": None,
        "inventory": inventory,
    }
