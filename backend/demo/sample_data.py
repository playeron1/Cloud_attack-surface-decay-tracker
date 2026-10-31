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
