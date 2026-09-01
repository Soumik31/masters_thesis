"""Discovery orchestrator — coordinates all resource discovery and returns a unified result."""

from __future__ import annotations

import logging

import boto3

from blast_radius_scanner.models import DiscoveryResult

from blast_radius_scanner.discovery.dynamodb import discover_dynamodb_tables
from blast_radius_scanner.discovery.ec2 import discover_ec2_instances, discover_security_groups
from blast_radius_scanner.discovery.exposure import (
    discover_lambda_exposures,
    discover_load_balancer_exposures,
)
from blast_radius_scanner.discovery.iam_roles import discover_iam_roles
from blast_radius_scanner.discovery.lambda_fn import discover_lambda_functions
from blast_radius_scanner.discovery.rds import discover_rds_instances
from blast_radius_scanner.discovery.s3 import discover_s3_buckets
from blast_radius_scanner.discovery.secrets import discover_secrets, discover_ssm_parameters
from blast_radius_scanner.discovery.vpc import (
    discover_internet_gateways,
    discover_nat_gateways,
    discover_route_tables,
    discover_vpc_endpoints,
)

logger = logging.getLogger(__name__)


def discover_all(session: boto3.Session, region: str) -> DiscoveryResult:
    """Run full resource discovery across all supported AWS resource types.

    Args:
        session: A configured boto3 session (with region + credentials).
        region: The AWS region being scanned (used for filtering S3 buckets).

    Returns:
        A DiscoveryResult containing all discovered resources.
    """
    logger.info("Starting resource discovery in region %s", region)

    # Step 1: Security groups first — other modules reference them
    ec2_client = session.client("ec2")
    security_groups = discover_security_groups(ec2_client)

    # Step 2: Discover all resource types
    ec2_instances = discover_ec2_instances(session, security_groups)
    rds_instances = discover_rds_instances(session, security_groups)
    s3_buckets = discover_s3_buckets(session, region)
    dynamodb_tables = discover_dynamodb_tables(session)
    lambda_functions = discover_lambda_functions(session, security_groups)
    # Annotate functions with how they can be reached, so entry point selection can be
    # restricted to resources an attacker could actually start from.
    if lambda_functions:
        exposures = discover_lambda_exposures(
            session, [fn.function_arn for fn in lambda_functions]
        )
        for fn in lambda_functions:
            fn.exposures = exposures.get(fn.function_arn, [])

    # Targets behind an internet-facing load balancer are reachable even without a public
    # IP of their own, which is the standard pattern for a private web instance.
    lb_exposures = discover_load_balancer_exposures(session)
    if lb_exposures:
        for inst in ec2_instances:
            for kind in lb_exposures.get(inst.instance_id, []):
                if kind not in inst.exposures:
                    inst.exposures.append(kind)
        for fn in lambda_functions:
            for kind in lb_exposures.get(fn.function_arn, []):
                if kind not in fn.exposures:
                    fn.exposures.append(kind)
    vpc_endpoints = discover_vpc_endpoints(session)
    nat_gateways = discover_nat_gateways(session)
    internet_gateways = discover_internet_gateways(session)
    route_tables = discover_route_tables(session)
    iam_roles = discover_iam_roles(session)
    secrets = discover_secrets(session)
    ssm_parameters = discover_ssm_parameters(session)

    result = DiscoveryResult(
        ec2_instances=ec2_instances,
        rds_instances=rds_instances,
        s3_buckets=s3_buckets,
        dynamodb_tables=dynamodb_tables,
        lambda_functions=lambda_functions,
        vpc_endpoints=vpc_endpoints,
        nat_gateways=nat_gateways,
        internet_gateways=internet_gateways,
        route_tables=route_tables,
        security_groups=security_groups,
        iam_roles=iam_roles,
        secrets=secrets,
        ssm_parameters=ssm_parameters,
    )

    logger.info(
        "Discovery complete: %d total resources found",
        result.total_resources,
    )
    return result
