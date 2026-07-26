"""Reachability mapper orchestrator — combines network, metadata, and IAM edges."""

from __future__ import annotations

import logging

import boto3

from blast_radius_scanner.models import DiscoveryResult
from blast_radius_scanner.reachability.iam import discover_iam_edges
from blast_radius_scanner.reachability.metadata import discover_metadata_edges
from blast_radius_scanner.reachability.network import Edge, discover_network_edges

logger = logging.getLogger(__name__)


def map_reachability(
    session: boto3.Session,
    discovery: DiscoveryResult,
) -> list[Edge]:
    """Map all reachability edges across network, metadata, and IAM dimensions.

    Args:
        session: boto3 session for IAM API calls.
        discovery: The complete discovery result.

    Returns:
        A combined list of all edges (network + metadata + IAM).
    """
    logger.info("Mapping reachability edges...")

    # 1. Network edges (SG + route-based)
    network_edges = discover_network_edges(discovery)

    # 2. Metadata edges (IMDS credential theft)
    metadata_edges = discover_metadata_edges(discovery)

    # 3. IAM edges (role policies → resources)
    iam_edges = discover_iam_edges(session, discovery)

    all_edges = network_edges + metadata_edges + iam_edges

    logger.info(
        "Total edges: %d (network=%d, metadata=%d, iam=%d)",
        len(all_edges),
        len(network_edges),
        len(metadata_edges),
        len(iam_edges),
    )

    return all_edges
