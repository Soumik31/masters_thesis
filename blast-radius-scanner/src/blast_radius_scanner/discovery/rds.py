"""Discover RDS instances with security groups and subnet information."""

from __future__ import annotations

import logging
from typing import Any

import boto3

from blast_radius_scanner.models import RDSInstance, SecurityGroup

logger = logging.getLogger(__name__)


def discover_rds_instances(
    session: boto3.Session,
    security_groups: dict[str, SecurityGroup],
) -> list[RDSInstance]:
    """Discover all RDS instances in the region."""
    rds_client = session.client("rds")
    instances: list[RDSInstance] = []

    paginator = rds_client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            instance = _build_rds_instance(db, security_groups)
            instances.append(instance)

    logger.info("Discovered %d RDS instances", len(instances))
    return instances


def _build_rds_instance(
    db: dict[str, Any],
    security_groups: dict[str, SecurityGroup],
) -> RDSInstance:
    """Build an RDSInstance model from raw boto3 response."""
    # Extract VPC security group IDs
    sg_ids = [
        vsg["VpcSecurityGroupId"]
        for vsg in db.get("VpcSecurityGroups", [])
        if vsg.get("Status") == "active"
    ]
    resolved_sgs = [security_groups[sg_id] for sg_id in sg_ids if sg_id in security_groups]

    # Extract subnet IDs from the DB subnet group
    subnet_ids: list[str] = []
    vpc_id: str | None = None
    subnet_group = db.get("DBSubnetGroup")
    if subnet_group:
        vpc_id = subnet_group.get("VpcId")
        subnet_ids = [
            subnet["SubnetIdentifier"]
            for subnet in subnet_group.get("Subnets", [])
        ]

    # Endpoint info
    endpoint = db.get("Endpoint", {})

    return RDSInstance(
        db_instance_id=db["DBInstanceIdentifier"],
        engine=db.get("Engine", "unknown"),
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        security_groups=resolved_sgs,
        publicly_accessible=db.get("PubliclyAccessible", False),
        endpoint=endpoint.get("Address"),
        port=endpoint.get("Port"),
    )
