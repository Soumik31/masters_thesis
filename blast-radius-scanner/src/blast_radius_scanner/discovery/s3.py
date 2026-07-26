"""Discover S3 buckets with public access block settings and policies."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3

from blast_radius_scanner.models import S3Bucket

logger = logging.getLogger(__name__)


def discover_s3_buckets(session: boto3.Session, region: str) -> list[S3Bucket]:
    """Discover all S3 buckets accessible from this account."""
    s3_client = session.client("s3")
    buckets: list[S3Bucket] = []

    try:
        response = s3_client.list_buckets()
    except Exception as e:
        logger.warning("Could not list S3 buckets: %s", e)
        return buckets

    for bucket_info in response.get("Buckets", []):
        bucket_name = bucket_info["Name"]
        bucket = _build_s3_bucket(s3_client, bucket_name, region)
        if bucket:
            buckets.append(bucket)

    logger.info("Discovered %d S3 buckets", len(buckets))
    return buckets


def _build_s3_bucket(s3_client: Any, bucket_name: str, region: str) -> S3Bucket | None:
    """Build an S3Bucket model, fetching public access block and policy."""
    # Determine bucket region
    bucket_region = _get_bucket_region(s3_client, bucket_name)

    # Only include buckets in the target region (or include all if region is None)
    if bucket_region and bucket_region != region:
        return None

    # Public access block
    public_access_block = _get_public_access_block(s3_client, bucket_name)

    # Bucket policy
    policy = _get_bucket_policy(s3_client, bucket_name)

    return S3Bucket(
        name=bucket_name,
        region=bucket_region,
        public_access_block=public_access_block,
        policy=policy,
    )


def _get_bucket_region(s3_client: Any, bucket_name: str) -> str | None:
    """Get the region where a bucket is located."""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        # LocationConstraint is None for us-east-1
        location = response.get("LocationConstraint")
        return location if location else "us-east-1"
    except Exception as e:
        logger.debug("Could not get location for bucket %s: %s", bucket_name, e)
        return None


def _get_public_access_block(s3_client: Any, bucket_name: str) -> dict[str, bool]:
    """Get the public access block configuration for a bucket."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})
        return {
            "BlockPublicAcls": config.get("BlockPublicAcls", False),
            "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
            "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
        }
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    except Exception as e:
        logger.debug("Could not get public access block for %s: %s", bucket_name, e)
        return {}


def _get_bucket_policy(s3_client: Any, bucket_name: str) -> dict[str, Any] | None:
    """Get the bucket policy as a parsed dict, or None if no policy exists."""
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = response.get("Policy", "")
        return json.loads(policy_str) if policy_str else None
    except Exception as e:
        # NoSuchBucketPolicy is a ClientError, not a named exception
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "NoSuchBucketPolicy":
            return None
        logger.debug("Could not get policy for bucket %s: %s", bucket_name, e)
        return None
