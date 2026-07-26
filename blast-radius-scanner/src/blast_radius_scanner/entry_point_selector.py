"""Auto entry point selection — ranks compute resources by exposure score."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from blast_radius_scanner.models import (
    DiscoveryResult,
    EC2Instance,
    LambdaFunction,
    RouteTable,
    SecurityGroup,
)

logger = logging.getLogger(__name__)


@dataclass
class EntryPointCandidate:
    """A compute resource scored as a potential entry point."""

    resource_id: str
    resource_type: str  # "ec2" or "lambda"
    name: str
    score: int  # 0-100
    reasons: list[str] = field(default_factory=list)


def select_entry_point(discovery: DiscoveryResult) -> list[EntryPointCandidate]:
    """Analyze all compute resources and rank them by exposure score.

    Scoring criteria (max 100 points):
    - Internet-facing (public IP): +25
    - Internet route (NAT/IGW in subnet route table): +20
    - IMDSv1 enabled (HttpTokens=optional): +20
    - Broad SG egress (0.0.0.0/0 rule): +15
    - Broad IAM role (many attached policies or wildcard actions): +20

    Returns candidates sorted by score descending.
    """
    candidates: list[EntryPointCandidate] = []

    # Build subnet → route table map for internet route checks
    subnet_rt_map, main_tables = _build_subnet_route_map(discovery.route_tables)

    # Score EC2 instances
    for inst in discovery.ec2_instances:
        if inst.state != "running":
            continue
        candidate = _score_ec2_instance(inst, subnet_rt_map, main_tables, discovery)
        candidates.append(candidate)

    # Score Lambda functions
    for fn in discovery.lambda_functions:
        candidate = _score_lambda_function(fn)
        candidates.append(candidate)

    # Sort by score descending
    candidates.sort(key=lambda c: c.score, reverse=True)

    return candidates


def _score_ec2_instance(
    inst: EC2Instance,
    subnet_rt_map: dict[str, RouteTable],
    main_tables: dict[str, RouteTable],
    discovery: DiscoveryResult,
) -> EntryPointCandidate:
    """Score an EC2 instance as a potential entry point."""
    score = 0
    reasons: list[str] = []

    # 1. Internet-facing (public IP)
    if inst.public_ip:
        score += 25
        reasons.append(f"public IP ({inst.public_ip})")

    # 2. Internet route in subnet's route table
    rt = subnet_rt_map.get(inst.subnet_id) or main_tables.get(inst.vpc_id)
    if rt and _has_internet_route(rt, discovery):
        score += 20
        reasons.append("internet egress via NAT/IGW")

    # 3. IMDSv1 enabled
    if inst.imds_http_tokens == "optional":
        score += 20
        reasons.append("IMDSv1 enabled")
    elif inst.imds_hop_limit > 1:
        score += 10
        reasons.append(f"IMDS hop_limit={inst.imds_hop_limit}")

    # 4. Broad SG egress (0.0.0.0/0)
    if _has_broad_egress(inst.security_groups):
        score += 15
        reasons.append("broad SG egress (0.0.0.0/0)")

    # 5. IAM role breadth
    if inst.iam_role_name:
        role_score, role_reason = _score_iam_role_breadth(inst.iam_role_name, discovery)
        score += role_score
        if role_reason:
            reasons.append(role_reason)

    # Cap at 100
    score = min(score, 100)

    return EntryPointCandidate(
        resource_id=inst.instance_id,
        resource_type="ec2",
        name=inst.name or inst.instance_id,
        score=score,
        reasons=reasons,
    )


def _score_lambda_function(fn: LambdaFunction) -> EntryPointCandidate:
    """Score a Lambda function as a potential entry point.

    Lambdas are generally lower risk as entry points since they don't have
    public IPs or IMDS, but their IAM role can still be broad.
    """
    score = 0
    reasons: list[str] = []

    # Lambdas are invocable (potential entry via API Gateway, event source, etc.)
    score += 10
    reasons.append("invocable function")

    # VPC-attached = can reach internal network
    if fn.vpc_id:
        score += 10
        reasons.append("VPC-attached (internal network access)")

        # Broad SG egress
        if _has_broad_egress(fn.security_groups):
            score += 10
            reasons.append("broad SG egress (0.0.0.0/0)")

    # IAM role breadth (approximate — we don't have policy details here)
    # We'll give it a base score for having a role
    if fn.role_name:
        score += 10
        reasons.append(f"has IAM role ({fn.role_name})")

    score = min(score, 100)

    return EntryPointCandidate(
        resource_id=fn.function_arn,
        resource_type="lambda",
        name=fn.function_name,
        score=score,
        reasons=reasons,
    )


def _has_broad_egress(security_groups: list[SecurityGroup]) -> bool:
    """Check if any SG has an egress rule allowing 0.0.0.0/0."""
    for sg in security_groups:
        for rule in sg.egress:
            for cidr in rule.cidr_blocks:
                if cidr in ("0.0.0.0/0", "::/0"):
                    return True
    return False


def _has_internet_route(route_table: RouteTable, discovery: DiscoveryResult) -> bool:
    """Check if a route table has a default route to the internet."""
    igw_ids = {igw.igw_id for igw in discovery.internet_gateways}
    nat_ids = {nat.nat_gateway_id for nat in discovery.nat_gateways}

    for route in route_table.routes:
        if route.destination_cidr != "0.0.0.0/0":
            continue
        if route.state != "active":
            continue
        if route.gateway_id and (route.gateway_id in igw_ids or route.gateway_id.startswith("igw-")):
            return True
        if route.nat_gateway_id and route.nat_gateway_id in nat_ids:
            return True
    return False


def _score_iam_role_breadth(role_name: str, discovery: DiscoveryResult) -> tuple[int, str]:
    """Estimate IAM role breadth based on what we know from discovery.

    We don't re-query IAM here (that happens in reachability), but we can
    check if the role is shared across multiple resources (indicating broad use).
    """
    # Count how many resources use this role
    usage_count = 0
    for inst in discovery.ec2_instances:
        if inst.iam_role_name == role_name:
            usage_count += 1
    for fn in discovery.lambda_functions:
        if fn.role_name == role_name:
            usage_count += 1

    if usage_count > 2:
        return 20, f"IAM role shared across {usage_count} resources (likely broad)"
    elif usage_count > 0:
        return 10, f"has IAM role ({role_name})"
    return 0, ""


def _build_subnet_route_map(
    route_tables: list[RouteTable],
) -> tuple[dict[str, RouteTable], dict[str, RouteTable]]:
    """Build subnet → route table and vpc → main route table maps."""
    subnet_map: dict[str, RouteTable] = {}
    main_tables: dict[str, RouteTable] = {}

    for rt in route_tables:
        if rt.is_main:
            main_tables[rt.vpc_id] = rt
        for subnet_id in rt.subnet_associations:
            subnet_map[subnet_id] = rt

    return subnet_map, main_tables
