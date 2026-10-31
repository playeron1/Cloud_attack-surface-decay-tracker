
import boto3

from botocore.exceptions import BotoCoreError, ClientError


def collect_aws_inventory(
    region_name="ap-south-1",
    profile_name=None
):
    """
    Collect read-only AWS resource inventory.

    Resources:
    - EC2 instances
    - EBS volumes
    - S3 buckets

    This function does not modify cloud resources.
    """

    session_options = {
        "region_name": region_name
    }

    if profile_name:
        session_options["profile_name"] = profile_name

    session = boto3.Session(**session_options)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        ec2 = session.client("ec2")
        s3 = session.client("s3")

        resources = []
        errors = []

        # 1. Collect EC2 instances
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:

                    resources.append({
                        "provider": "aws",
                        "resource_type": "ec2_instance",
                        "resource_id": instance["InstanceId"],
                        "state": instance["State"]["Name"],
                        "instance_type": instance["InstanceType"],
                        "launch_time": (
                            instance["LaunchTime"].isoformat()
                            if instance.get("LaunchTime")
                            else None
                        ),
                        "public_ip": instance.get("PublicIpAddress"),
                        "private_ip": instance.get("PrivateIpAddress"),
                        "vpc_id": instance.get("VpcId"),
                        "tags": {
                            tag["Key"]: tag["Value"]
                            for tag in instance.get("Tags", [])
                        }
                    })

        # 2. Collect EBS volumes
        paginator = ec2.get_paginator("describe_volumes")

        for page in paginator.paginate():
            for volume in page["Volumes"]:

                resources.append({
                    "provider": "aws",
                    "resource_type": "ebs_volume",
                    "resource_id": volume["VolumeId"],
                    "state": volume["State"],
                    "size_gb": volume["Size"],
                    "encrypted": volume["Encrypted"],
                    "attachment_count": len(
                        volume.get("Attachments", [])
                    ),
                    "create_time": volume["CreateTime"].isoformat(),
                    "tags": {
                        tag["Key"]: tag["Value"]
                        for tag in volume.get("Tags", [])
                    }
                })

        # 3. Collect S3 bucket metadata
        bucket_response = s3.list_buckets()

        for bucket in bucket_response.get("Buckets", []):
            bucket_name = bucket["Name"]

            bucket_data = {
                "provider": "aws",
                "resource_type": "s3_bucket",
                "resource_id": bucket_name,
                "creation_date": (
                    bucket["CreationDate"].isoformat()
                    if bucket.get("CreationDate")
                    else None
                )
            }

            # Determine bucket region
            try:
                location = s3.get_bucket_location(
                    Bucket=bucket_name
                )

                bucket_data["region"] = (
                    location.get("LocationConstraint") or "us-east-1"
                )

            except ClientError as error:
                bucket_data["region"] = "unknown"
                errors.append({
                    "resource": bucket_name,
                    "operation": "get_bucket_location",
                    "error": error.response["Error"]["Code"]
                })

            # Inspect bucket-level public access block
            try:
                public_block = s3.get_public_access_block(
                    Bucket=bucket_name
                )

                bucket_data["public_access_block"] = (
                    public_block["PublicAccessBlockConfiguration"]
                )
                bucket_data["public_access_block_status"] = "configured"

            except ClientError as error:
                error_code = error.response["Error"]["Code"]

                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    bucket_data["public_access_block"] = None
                    bucket_data["public_access_block_status"] = (
                        "not_configured"
                    )
                else:
                    bucket_data["public_access_block"] = None
                    bucket_data["public_access_block_status"] = "unknown"

                    errors.append({
                        "resource": bucket_name,
                        "operation": "get_public_access_block",
                        "error": error_code
                    })

            # Inspect bucket policy public status
            try:
                policy_status = s3.get_bucket_policy_status(
                    Bucket=bucket_name
                )

                bucket_data["bucket_policy_public"] = (
                    policy_status["PolicyStatus"]["IsPublic"]
                )

            except ClientError as error:
                error_code = error.response["Error"]["Code"]

                if error_code == "NoSuchBucketPolicy":
                    bucket_data["bucket_policy_public"] = None
                    bucket_data["policy_status"] = "no_bucket_policy"
                else:
                    bucket_data["bucket_policy_public"] = None
                    bucket_data["policy_status"] = "unknown"

                    errors.append({
                        "resource": bucket_name,
                        "operation": "get_bucket_policy_status",
                        "error": error_code
                    })

            resources.append(bucket_data)

        return {
            "provider": "aws",
            "account_id": identity["Account"],
            "region": region_name,
            "total_resources": len(resources),
            "resources": resources,
            "errors": errors
        }

    except (BotoCoreError, ClientError) as error:
        raise RuntimeError(
            f"AWS inventory collection failed: {error}"
        ) from error
