"""Discover VPC endpoints, NAT Gateways, Internet Gateways, and Route Tables."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3

from blast_radius_scanner.models import (
    InternetGateway,
    NATGateway,
    Route,
    RouteTable,
    VPCEndpoint,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# VPC Endpoints
# ---------------------------------------------------------------------------


def discover_vpc_endpoints(session: boto3.Session) -> list[VPCEndpoint]:
    """Discover all VPC endpoints in the region."""
    ec2_client = session.client("ec2")
    endpoints: list[VPCEndpoint] = []

    paginator = ec2_client.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate():
        for ep in page.get("VpcEndpoints", []):
            endpoint = _build_vpc_endpoint(ep)
            endpoints.append(endpoint)

    logger.info("Discovered %d VPC endpoints", len(endpoints))
    return endpoints


def _build_vpc_endpoint(ep: dict[str, Any]) -> VPCEndpoint:
    """Build a VPCEndpoint model from raw boto3 response."""
    # Parse policy document if present
    policy = None
    policy_doc = ep.get("PolicyDocument")
    if policy_doc:
        try:
            policy = json.loads(policy_doc) if isinstance(policy_doc, str) else policy_doc
        except (json.JSONDecodeError, TypeError):
            pass

    return VPCEndpoint(
        endpoint_id=ep["VpcEndpointId"],
        service_name=ep.get("ServiceName", ""),
        vpc_id=ep.get("VpcId", ""),
        endpoint_type=ep.get("VpcEndpointType", "Gateway"),
        route_table_ids=ep.get("RouteTableIds", []),
        subnet_ids=ep.get("SubnetIds", []),
        policy=policy,
    )


# ---------------------------------------------------------------------------
# NAT Gateways
# ---------------------------------------------------------------------------


def discover_nat_gateways(session: boto3.Session) -> list[NATGateway]:
    """Discover all NAT Gateways in the region."""
    ec2_client = session.client("ec2")
    nat_gateways: list[NATGateway] = []

    paginator = ec2_client.get_paginator("describe_nat_gateways")
    for page in paginator.paginate():
        for ngw in page.get("NatGateways", []):
            nat_gw = _build_nat_gateway(ngw)
            nat_gateways.append(nat_gw)

    logger.info("Discovered %d NAT Gateways", len(nat_gateways))
    return nat_gateways


def _build_nat_gateway(ngw: dict[str, Any]) -> NATGateway:
    """Build a NATGateway model from raw boto3 response."""
    # Extract public IP from addresses
    public_ip = None
    for addr in ngw.get("NatGatewayAddresses", []):
        if addr.get("PublicIp"):
            public_ip = addr["PublicIp"]
            break

    return NATGateway(
        nat_gateway_id=ngw["NatGatewayId"],
        vpc_id=ngw.get("VpcId", ""),
        subnet_id=ngw.get("SubnetId", ""),
        public_ip=public_ip,
        state=ngw.get("State", "unknown"),
    )


# ---------------------------------------------------------------------------
# Internet Gateways
# ---------------------------------------------------------------------------


def discover_internet_gateways(session: boto3.Session) -> list[InternetGateway]:
    """Discover all Internet Gateways in the region."""
    ec2_client = session.client("ec2")
    igws: list[InternetGateway] = []

    paginator = ec2_client.get_paginator("describe_internet_gateways")
    for page in paginator.paginate():
        for igw in page.get("InternetGateways", []):
            gateway = InternetGateway(
                igw_id=igw["InternetGatewayId"],
                vpc_ids=[
                    att["VpcId"]
                    for att in igw.get("Attachments", [])
                    if att.get("State") == "available"
                ],
            )
            igws.append(gateway)

    logger.info("Discovered %d Internet Gateways", len(igws))
    return igws


# ---------------------------------------------------------------------------
# Route Tables
# ---------------------------------------------------------------------------


def discover_route_tables(session: boto3.Session) -> list[RouteTable]:
    """Discover all route tables in the region."""
    ec2_client = session.client("ec2")
    route_tables: list[RouteTable] = []

    paginator = ec2_client.get_paginator("describe_route_tables")
    for page in paginator.paginate():
        for rt in page.get("RouteTables", []):
            route_table = _build_route_table(rt)
            route_tables.append(route_table)

    logger.info("Discovered %d route tables", len(route_tables))
    return route_tables


def _build_route_table(rt: dict[str, Any]) -> RouteTable:
    """Build a RouteTable model from raw boto3 response."""
    # Determine subnet associations
    associations = rt.get("Associations", [])
    subnet_associations = [
        assoc["SubnetId"]
        for assoc in associations
        if assoc.get("SubnetId")
    ]
    is_main = any(assoc.get("Main", False) for assoc in associations)

    # Parse routes
    routes = [_build_route(r) for r in rt.get("Routes", [])]

    return RouteTable(
        route_table_id=rt["RouteTableId"],
        vpc_id=rt.get("VpcId", ""),
        subnet_associations=subnet_associations,
        routes=routes,
        is_main=is_main,
    )


def _build_route(r: dict[str, Any]) -> Route:
    """Build a Route model from raw boto3 route entry."""
    return Route(
        destination_cidr=r.get("DestinationCidrBlock"),
        destination_prefix_list_id=r.get("DestinationPrefixListId"),
        gateway_id=r.get("GatewayId"),
        nat_gateway_id=r.get("NatGatewayId"),
        vpc_endpoint_id=r.get("VpcEndpointId"),
        instance_id=r.get("InstanceId"),
        state=r.get("State", "active"),
    )
