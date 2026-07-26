"""Graph builder - constructs a networkx DiGraph from discovered resources and reachability edges."""

from __future__ import annotations

import logging

import networkx as nx

from blast_radius_scanner.models import DiscoveryResult
from blast_radius_scanner.reachability.network import Edge

logger = logging.getLogger(__name__)


def build_attack_graph(
    discovery: DiscoveryResult,
    edges: list[Edge],
) -> nx.DiGraph:
    """Build a directed attack graph from discovery results and reachability edges."""
    G = nx.DiGraph()

    _add_resource_nodes(G, discovery)
    _add_iam_role_nodes(G, discovery)
    G.add_node("Internet", resource_type="external", resource_id="Internet", label="Internet")

    for edge in edges:
        if not G.has_node(edge.source_id):
            _add_dynamic_node(G, edge.source_id)
        if not G.has_node(edge.target_id):
            _add_dynamic_node(G, edge.target_id)

        G.add_edge(
            edge.source_id,
            edge.target_id,
            edge_type=edge.edge_type,
            port=edge.port,
            protocol=edge.protocol,
            label=edge.label,
            **edge.details,
        )

    logger.info("Built attack graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    return G


def _add_resource_nodes(G: nx.DiGraph, discovery: DiscoveryResult) -> None:
    for inst in discovery.ec2_instances:
        G.add_node(inst.instance_id, resource_type="ec2", resource_id=inst.instance_id,
                   label=inst.name or inst.instance_id, vpc_id=inst.vpc_id, state=inst.state)

    for rds in discovery.rds_instances:
        G.add_node(rds.db_instance_id, resource_type="rds", resource_id=rds.db_instance_id,
                   label=rds.db_instance_id, engine=rds.engine, vpc_id=rds.vpc_id or "")

    for bucket in discovery.s3_buckets:
        node_id = f"s3:{bucket.name}"
        G.add_node(node_id, resource_type="s3", resource_id=bucket.name, label=bucket.name)

    for table in discovery.dynamodb_tables:
        node_id = f"dynamodb:{table.table_name}"
        G.add_node(node_id, resource_type="dynamodb", resource_id=table.table_name, label=table.table_name)

    for fn in discovery.lambda_functions:
        G.add_node(fn.function_arn, resource_type="lambda", resource_id=fn.function_name,
                   label=fn.function_name, vpc_id=fn.vpc_id or "")

    for ep in discovery.vpc_endpoints:
        G.add_node(ep.endpoint_id, resource_type="vpc_endpoint", resource_id=ep.endpoint_id,
                   label=f"{ep.endpoint_type}:{ep.service_name}")

    for nat in discovery.nat_gateways:
        G.add_node(nat.nat_gateway_id, resource_type="nat_gateway",
                   resource_id=nat.nat_gateway_id, label=nat.nat_gateway_id)

    for igw in discovery.internet_gateways:
        G.add_node(igw.igw_id, resource_type="internet_gateway",
                   resource_id=igw.igw_id, label=igw.igw_id)

    for rt in discovery.route_tables:
        G.add_node(rt.route_table_id, resource_type="route_table",
                   resource_id=rt.route_table_id, label=rt.route_table_id)


def _add_iam_role_nodes(G: nx.DiGraph, discovery: DiscoveryResult) -> None:
    role_names: set[str] = set()
    for inst in discovery.ec2_instances:
        if inst.iam_role_name:
            role_names.add(inst.iam_role_name)
    for fn in discovery.lambda_functions:
        if fn.role_name:
            role_names.add(fn.role_name)

    for role_name in role_names:
        node_id = f"iam_role:{role_name}"
        G.add_node(node_id, resource_type="iam_role", resource_id=role_name, label=f"Role: {role_name}")


def _add_dynamic_node(G: nx.DiGraph, node_id: str) -> None:
    if node_id.startswith("iam_role:"):
        role_name = node_id.split(":", 1)[1]
        G.add_node(node_id, resource_type="iam_role", resource_id=role_name, label=f"Role: {role_name}")
    elif node_id.startswith("s3:"):
        name = node_id.split(":", 1)[1]
        G.add_node(node_id, resource_type="s3", resource_id=name, label=name)
    elif node_id.startswith("dynamodb:"):
        name = node_id.split(":", 1)[1]
        G.add_node(node_id, resource_type="dynamodb", resource_id=name, label=name)
    else:
        G.add_node(node_id, resource_type="unknown", resource_id=node_id, label=node_id)
