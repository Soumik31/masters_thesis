"""Metadata reachability — IMDS credential theft edges via SSRF."""

from __future__ import annotations

import logging

from blast_radius_scanner.models import DiscoveryResult, EC2Instance
from blast_radius_scanner.reachability.network import Edge

logger = logging.getLogger(__name__)


def discover_metadata_edges(discovery: DiscoveryResult) -> list[Edge]:
    """Determine metadata-based edges (IMDS credential theft).

    If an EC2 instance has:
    - HttpTokens = "optional" (IMDSv1 enabled) → SSRF can steal credentials
    - The instance has an IAM role attached

    Then any resource that can reach this instance on port 80/443 (HTTP)
    can potentially steal its IAM credentials via SSRF → 169.254.169.254.

    We model this as: instance → "iam_role:<role_name>" (credential theft path).
    The IAM edge mapper will then connect that role to the resources it can access.
    """
    edges: list[Edge] = []

    for inst in discovery.ec2_instances:
        if inst.state != "running":
            continue
        if not inst.iam_role_name:
            continue

        # IMDSv1 enabled = credential theft possible
        if inst.imds_http_tokens == "optional":
            edges.append(Edge(
                source_id=inst.instance_id,
                target_id=f"iam_role:{inst.iam_role_name}",
                edge_type="metadata",
                label="IMDS credential theft (IMDSv1)",
                details={
                    "imds_version": "v1",
                    "http_tokens": "optional",
                    "hop_limit": inst.imds_hop_limit,
                    "role_name": inst.iam_role_name,
                },
            ))
        elif inst.imds_hop_limit > 1:
            # IMDSv2 with high hop limit — still exploitable in container scenarios
            edges.append(Edge(
                source_id=inst.instance_id,
                target_id=f"iam_role:{inst.iam_role_name}",
                edge_type="metadata",
                label=f"IMDS reachable (hop_limit={inst.imds_hop_limit})",
                details={
                    "imds_version": "v2",
                    "http_tokens": "required",
                    "hop_limit": inst.imds_hop_limit,
                    "role_name": inst.iam_role_name,
                },
            ))

    logger.info("Discovered %d metadata edges", len(edges))
    return edges
