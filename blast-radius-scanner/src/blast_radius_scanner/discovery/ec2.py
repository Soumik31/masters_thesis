"""Discover EC2 instances with security groups, subnets, IAM profiles, and IMDS settings."""

from __future__ import annotations

import logging
from typing import Any

import boto3

from blast_radius_scanner.models import (
    EC2Instance,
    SecurityGroup,
    SecurityGroupRule,
)

logger = logging.getLogger(__name__)


def _parse_sg_rule(rule: dict[str, Any]) -> SecurityGroupRule:
    """Parse a raw boto3 security group rule into our model."""
    cidr_blocks = [r["CidrIp"] for r in rule.get("IpRanges", [])]
    cidr_blocks += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
    source_sg_ids = [r["GroupId"] for r in rule.get("UserIdGroupPairs", [])]
    prefix_list_ids = [r["PrefixListId"] for r in rule.get("PrefixListIds", [])]

    return SecurityGroupRule(
        protocol=rule.get("IpProtocol", "-1"),
        from_port=rule.get("FromPort", -1),
        to_port=rule.get("ToPort", -1),
        cidr_blocks=cidr_blocks,
        source_sg_ids=source_sg_ids,
        prefix_list_ids=prefix_list_ids,
    )


def _parse_security_group(sg: dict[str, Any]) -> SecurityGroup:
    """Parse a raw boto3 security group response into our model."""
    return SecurityGroup(
        group_id=sg["GroupId"],
        group_name=sg.get("GroupName", ""),
        vpc_id=sg.get("VpcId", ""),
        ingress=[_parse_sg_rule(r) for r in sg.get("IpPermissions", [])],
        egress=[_parse_sg_rule(r) for r in sg.get("IpPermissionsEgress", [])],
    )


def discover_security_groups(ec2_client: Any) -> dict[str, SecurityGroup]:
    """Fetch all security groups in the region and return them indexed by group ID."""
    security_groups: dict[str, SecurityGroup] = {}
    paginator = ec2_client.get_paginator("describe_security_groups")

    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            parsed = _parse_security_group(sg)
            security_groups[parsed.group_id] = parsed

    logger.info("Discovered %d security groups", len(security_groups))
    return security_groups


def discover_ec2_instances(
    session: boto3.Session,
    security_groups: dict[str, SecurityGroup],
) -> list[EC2Instance]:
    """Discover all EC2 instances with their metadata, SGs, and IMDS configuration."""
    ec2_client = session.client("ec2")
    iam_client = session.client("iam")

    instances: list[EC2Instance] = []
    paginator = ec2_client.get_paginator("describe_instances")

    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                instance = _build_ec2_instance(inst, security_groups, iam_client)
                instances.append(instance)

    logger.info("Discovered %d EC2 instances", len(instances))
    return instances


def _build_ec2_instance(
    inst: dict[str, Any],
    security_groups: dict[str, SecurityGroup],
    iam_client: Any,
) -> EC2Instance:
    """Build an EC2Instance model from raw boto3 instance data."""
    instance_id = inst["InstanceId"]
    state = inst["State"]["Name"]

    # Extract name from tags
    name = ""
    for tag in inst.get("Tags", []):
        if tag["Key"] == "Name":
            name = tag["Value"]
            break

    # Attach resolved security groups
    sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
    resolved_sgs = [security_groups[sg_id] for sg_id in sg_ids if sg_id in security_groups]

    # IAM instance profile
    iam_profile_arn: str | None = None
    iam_role_name: str | None = None
    if "IamInstanceProfile" in inst:
        iam_profile_arn = inst["IamInstanceProfile"].get("Arn")
        iam_role_name = _resolve_role_from_instance_profile(iam_profile_arn, iam_client)

    # IMDS settings
    metadata_options = inst.get("MetadataOptions", {})
    imds_http_tokens = metadata_options.get("HttpTokens", "optional")
    imds_hop_limit = metadata_options.get("HttpPutResponseHopLimit", 1)

    return EC2Instance(
        instance_id=instance_id,
        name=name,
        state=state,
        vpc_id=inst.get("VpcId", ""),
        subnet_id=inst.get("SubnetId", ""),
        private_ip=inst.get("PrivateIpAddress"),
        public_ip=inst.get("PublicIpAddress"),
        security_groups=resolved_sgs,
        iam_instance_profile_arn=iam_profile_arn,
        iam_role_name=iam_role_name,
        imds_http_tokens=imds_http_tokens,
        imds_hop_limit=imds_hop_limit,
    )


def _resolve_role_from_instance_profile(
    profile_arn: str | None,
    iam_client: Any,
) -> str | None:
    """Given an instance profile ARN, resolve the attached IAM role name."""
    if not profile_arn:
        return None

    # Extract instance profile name from ARN
    # Format: arn:aws:iam::123456789012:instance-profile/profile-name
    try:
        profile_name = profile_arn.split("/")[-1]
        response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        roles = response["InstanceProfile"].get("Roles", [])
        if roles:
            return roles[0]["RoleName"]
    except Exception as e:
        logger.warning("Could not resolve role for instance profile %s: %s", profile_arn, e)

    return None
