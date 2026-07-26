"""Discover Lambda functions with IAM roles and VPC configuration."""

from __future__ import annotations

import logging
from typing import Any

import boto3

from blast_radius_scanner.models import LambdaFunction, SecurityGroup

logger = logging.getLogger(__name__)


def discover_lambda_functions(
    session: boto3.Session,
    security_groups: dict[str, SecurityGroup],
) -> list[LambdaFunction]:
    """Discover all Lambda functions in the region."""
    lambda_client = session.client("lambda")
    functions: list[LambdaFunction] = []

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            function = _build_lambda_function(fn, security_groups)
            functions.append(function)

    logger.info("Discovered %d Lambda functions", len(functions))
    return functions


def _build_lambda_function(
    fn: dict[str, Any],
    security_groups: dict[str, SecurityGroup],
) -> LambdaFunction:
    """Build a LambdaFunction model from raw boto3 response."""
    role_arn = fn.get("Role", "")
    # Extract role name from ARN: arn:aws:iam::123456789012:role/role-name
    role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn

    # VPC configuration
    vpc_config = fn.get("VpcConfig", {})
    vpc_id = vpc_config.get("VpcId") or None
    subnet_ids = vpc_config.get("SubnetIds", [])
    sg_ids = vpc_config.get("SecurityGroupIds", [])

    resolved_sgs = [security_groups[sg_id] for sg_id in sg_ids if sg_id in security_groups]

    return LambdaFunction(
        function_name=fn["FunctionName"],
        function_arn=fn["FunctionArn"],
        runtime=fn.get("Runtime"),
        role_arn=role_arn,
        role_name=role_name,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        security_groups=resolved_sgs,
    )
