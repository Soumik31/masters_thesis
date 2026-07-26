"""Network reachability — determines edges based on security group rules and route tables."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from blast_radius_scanner.models import (
    DiscoveryResult,
    RouteTable,
    SecurityGroup,
    SecurityGroupRule,
)

logger = logging.getLogger(__name__)


@dataclass
class Edge:
    """A directed edge in the attack graph."""

    source_id: str
    target_id: str
    edge_type: str  # "network", "route", "metadata", "iam"
    port: int | None = None
    protocol: str | None = None
    label: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def discover_network_edges(discovery: DiscoveryResult) -> list[Edge]:
    """Determine all network-level reachability edges.

    Logic:
    - EC2 -> EC2: source SG egress allows traffic AND target SG ingress allows it
    - EC2 -> RDS: source SG egress allows traffic AND RDS SG ingress allows it
    - EC2 -> Internet: route table has 0.0.0.0/0 via NAT/IGW
    - Lambda (VPC) -> EC2/RDS: same SG logic as EC2
    """
    edges: list[Edge] = []

    # Build lookup: subnet_id -> route table (with main RT fallback)
    subnet_route_map, main_tables = _build_subnet_route_map(discovery.route_tables)

    # All "compute" sources: EC2 instances + VPC-attached Lambdas
    compute_sources = _get_compute_sources(discovery)

    # All network targets: EC2 instances + RDS instances
    network_targets = _get_network_targets(discovery)

    for source in compute_sources:
        source_id = source["id"]
        source_sgs = source["security_groups"]
        source_subnet = source["subnet_id"]
        source_vpc = source["vpc_id"]

        # Check connectivity to each network target
        for target in network_targets:
            if target["id"] == source_id:
                continue  # skip self

            target_id = target["id"]
            target_sgs = target["security_groups"]
            target_vpc = target["vpc_id"]

            # Must be in the same VPC for direct network connectivity
            if source_vpc != target_vpc:
                continue

            # Check SG rules: egress from source allows + ingress on target allows
            allowed_ports = _check_sg_connectivity(source_sgs, target_sgs)
            for port, protocol in allowed_ports:
                edges.append(Edge(
                    source_id=source_id,
                    target_id=target_id,
                    edge_type="network",
                    port=port,
                    protocol=protocol,
                    label=f"{protocol}/{port}",
                ))

        # Check internet reachability via route table
        route_table = _get_route_table_for_subnet(
            source_subnet, source_vpc, subnet_route_map, main_tables
        )
        if route_table:
            internet_route = _has_internet_route(route_table, discovery)
            if internet_route:
                edges.append(Edge(
                    source_id=source_id,
                    target_id="Internet",
                    edge_type="route",
                    label=f"via {internet_route}",
                    details={"gateway": internet_route},
                ))

    logger.info("Discovered %d network/route edges", len(edges))
    return edges


def _get_compute_sources(discovery: DiscoveryResult) -> list[dict[str, Any]]:
    """Build a list of compute sources (EC2 + VPC Lambdas) with their SG and subnet info."""
    sources: list[dict[str, Any]] = []

    for inst in discovery.ec2_instances:
        if inst.state != "running":
            continue
        sources.append({
            "id": inst.instance_id,
            "security_groups": inst.security_groups,
            "subnet_id": inst.subnet_id,
            "vpc_id": inst.vpc_id,
        })

    for fn in discovery.lambda_functions:
        if fn.vpc_id:  # Only VPC-attached Lambdas have network edges
            sources.append({
                "id": fn.function_arn,
                "security_groups": fn.security_groups,
                "subnet_id": fn.subnet_ids[0] if fn.subnet_ids else None,
                "vpc_id": fn.vpc_id,
            })

    return sources


def _get_network_targets(discovery: DiscoveryResult) -> list[dict[str, Any]]:
    """Build a list of network targets (EC2 + RDS) with their SG and VPC info."""
    targets: list[dict[str, Any]] = []

    for inst in discovery.ec2_instances:
        if inst.state != "running":
            continue
        targets.append({
            "id": inst.instance_id,
            "security_groups": inst.security_groups,
            "vpc_id": inst.vpc_id,
        })

    for rds in discovery.rds_instances:
        targets.append({
            "id": rds.db_instance_id,
            "security_groups": rds.security_groups,
            "vpc_id": rds.vpc_id,
        })

    return targets


def _build_subnet_route_map(
    route_tables: list[RouteTable],
) -> tuple[dict[str, RouteTable], dict[str, RouteTable]]:
    """Map subnet IDs to their associated route table, and track main RTs per VPC.

    Returns:
        (subnet_map, main_tables) where:
        - subnet_map: subnet_id -> explicitly associated RouteTable
        - main_tables: vpc_id -> main RouteTable (fallback for subnets without explicit association)
    """
    subnet_map: dict[str, RouteTable] = {}
    main_tables: dict[str, RouteTable] = {}

    for rt in route_tables:
        if rt.is_main:
            main_tables[rt.vpc_id] = rt
        for subnet_id in rt.subnet_associations:
            subnet_map[subnet_id] = rt

    return subnet_map, main_tables


def _get_route_table_for_subnet(
    subnet_id: str | None,
    vpc_id: str,
    subnet_map: dict[str, RouteTable],
    main_tables: dict[str, RouteTable],
) -> RouteTable | None:
    """Get the route table for a subnet, falling back to the VPC's main RT."""
    if not subnet_id:
        return main_tables.get(vpc_id)

    # Explicit association takes priority
    if subnet_id in subnet_map:
        return subnet_map[subnet_id]

    # Fall back to main route table for the VPC
    return main_tables.get(vpc_id)


def _check_sg_connectivity(
    source_sgs: list[SecurityGroup],
    target_sgs: list[SecurityGroup],
) -> list[tuple[int, str]]:
    """Check if source SG egress allows traffic that target SG ingress also allows.

    Returns list of (port, protocol) tuples that are mutually allowed.

    Logic:
    1. Direct SG reference: target ingress references source SG -> allowed
    2. CIDR overlap: source egress allows 0.0.0.0/0 (all outbound) AND
       target ingress allows intra-VPC traffic (0.0.0.0/0 or 10.0.0.0/8 or private range)
       -> allowed on the ingress port
    3. Port range matching: egress port range overlaps with ingress port range
    """
    allowed: list[tuple[int, str]] = []

    source_sg_ids = {sg.group_id for sg in source_sgs}

    # 1. Check if any target ingress rule references the source SG directly
    #    This is the most precise check — AWS evaluates this regardless of CIDRs
    for target_sg in target_sgs:
        for rule in target_sg.ingress:
            for ref_sg_id in rule.source_sg_ids:
                if ref_sg_id in source_sg_ids:
                    # Direct SG reference — traffic is allowed on these ports
                    ports = _get_representative_ports(rule)
                    for port in ports:
                        allowed.append((port, rule.protocol))

    # 2. CIDR-based check: egress must allow outbound AND ingress must allow inbound
    #    Since both source and target are in the same VPC, we check:
    #    - Source egress allows all destinations (0.0.0.0/0) OR allows VPC CIDR
    #    - Target ingress allows all sources (0.0.0.0/0) OR allows VPC CIDR/private ranges
    #    Simplified: if egress is open (0.0.0.0/0) and ingress is open (0.0.0.0/0 or private)
    source_has_open_egress = _has_open_egress(source_sgs)

    if source_has_open_egress:
        for target_sg in target_sgs:
            for rule in target_sg.ingress:
                # Check if ingress allows traffic from private/VPC ranges
                if _allows_private_sources(rule.cidr_blocks):
                    ports = _get_representative_ports(rule)
                    for port in ports:
                        allowed.append((port, rule.protocol))

    # Deduplicate
    return list(set(allowed))


def _has_open_egress(sgs: list[SecurityGroup]) -> bool:
    """Check if any SG has an egress rule allowing all outbound traffic."""
    for sg in sgs:
        for rule in sg.egress:
            if rule.protocol == "-1" and _allows_all_destinations(rule.cidr_blocks):
                return True
            if _allows_all_destinations(rule.cidr_blocks):
                return True
    return False


def _allows_private_sources(cidrs: list[str]) -> bool:
    """Check if CIDR list includes private ranges or 0.0.0.0/0 (which covers everything).

    In a VPC context, if ingress allows 0.0.0.0/0 or any RFC1918 range,
    then intra-VPC traffic is accepted.
    """
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.")

    for cidr in cidrs:
        if cidr in ("0.0.0.0/0", "::/0"):
            return True
        if cidr.startswith(private_prefixes):
            return True
    return False


def _get_representative_ports(rule: SecurityGroupRule) -> list[int]:
    """Get representative ports from a rule.

    - All traffic (-1/-1): returns [-1]
    - Single port (e.g., 443/443): returns [443]
    - Port range (e.g., 1024-65535): returns [from_port] as representative
      (the edge label will show the range via protocol/port)
    """
    if rule.from_port == -1 and rule.to_port == -1:
        return [-1]  # all ports
    if rule.from_port == rule.to_port:
        return [rule.from_port]
    # For ranges, return from_port as representative
    return [rule.from_port]


def _port_ranges_overlap(
    egress_from: int, egress_to: int,
    ingress_from: int, ingress_to: int,
) -> bool:
    """Check if two port ranges overlap."""
    if egress_from == -1 or ingress_from == -1:
        return True  # -1 means all ports
    return egress_from <= ingress_to and ingress_from <= egress_to


def _allows_all_destinations(cidrs: list[str]) -> bool:
    """Check if the CIDR list effectively allows all destinations."""
    for cidr in cidrs:
        if cidr in ("0.0.0.0/0", "::/0"):
            return True
    return False


def _has_internet_route(route_table: RouteTable, discovery: DiscoveryResult) -> str | None:
    """Check if the route table has a route to the internet (0.0.0.0/0 via IGW or NAT)."""
    igw_ids = {igw.igw_id for igw in discovery.internet_gateways}
    nat_ids = {nat.nat_gateway_id for nat in discovery.nat_gateways}

    for route in route_table.routes:
        if route.destination_cidr != "0.0.0.0/0":
            continue
        if route.state != "active":
            continue
        if route.gateway_id and route.gateway_id in igw_ids:
            return f"igw:{route.gateway_id}"
        if route.nat_gateway_id and route.nat_gateway_id in nat_ids:
            return f"nat:{route.nat_gateway_id}"
        # igw- prefix without being in our list (e.g. local gateways)
        if route.gateway_id and route.gateway_id.startswith("igw-"):
            return f"igw:{route.gateway_id}"

    return None
