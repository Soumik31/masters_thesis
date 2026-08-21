"""Reachability mapper orchestrator — combines network, identity/metadata, and IAM edges."""

from __future__ import annotations

import logging

import boto3

from blast_radius_scanner.models import DiscoveryResult
from blast_radius_scanner.reachability.iam import discover_iam_edges
from blast_radius_scanner.reachability.identity import discover_identity_edges
from blast_radius_scanner.reachability.metadata import discover_metadata_edges
from blast_radius_scanner.reachability.network import Edge, discover_network_edges

logger = logging.getLogger(__name__)

# Threat model identifiers
TM_CODE_EXEC = "code_exec"
TM_SSRF = "ssrf"
THREAT_MODELS = (TM_CODE_EXEC, TM_SSRF)

THREAT_MODEL_LABELS = {
    TM_CODE_EXEC: "TM1 code execution on the entry point",
    TM_SSRF: "TM2 SSRF only (no code execution)",
}


def map_reachability_all(
    session: boto3.Session,
    discovery: DiscoveryResult,
) -> dict[str, list[Edge]]:
    """Map reachability edges for every threat model in one pass.

    Network and IAM edge discovery are threat-model independent, so they are computed
    once and shared. Only the compute -> role edge differs:

    - code_exec: unconditional identity edges (EC2 and Lambda)
    - ssrf:      IMDS-gated metadata edges (EC2 only, IMDSv1 or hop_limit > 1)

    Sharing the IAM pass matters because it is the only part that makes AWS API calls.

    Returns:
        A mapping of threat model name -> complete edge list.
    """
    logger.info("Mapping reachability edges...")

    network_edges = discover_network_edges(discovery)
    iam_edges = discover_iam_edges(session, discovery)

    identity_edges = discover_identity_edges(discovery)
    metadata_edges = discover_metadata_edges(discovery)

    edge_sets = {
        TM_CODE_EXEC: network_edges + identity_edges + iam_edges,
        TM_SSRF: network_edges + metadata_edges + iam_edges,
    }

    for tm, edges in edge_sets.items():
        logger.info("Threat model %s: %d total edges", tm, len(edges))

    return edge_sets


def map_reachability(
    session: boto3.Session,
    discovery: DiscoveryResult,
    threat_model: str = TM_CODE_EXEC,
) -> list[Edge]:
    """Map all reachability edges for a single threat model.

    Args:
        session: boto3 session for IAM API calls.
        discovery: The complete discovery result.
        threat_model: One of THREAT_MODELS.

    Returns:
        A combined list of all edges for the requested threat model.
    """
    if threat_model not in THREAT_MODELS:
        raise ValueError(
            f"Unknown threat model {threat_model!r}; expected one of {THREAT_MODELS}"
        )
    return map_reachability_all(session, discovery)[threat_model]
