"""Identity reachability — execution-role credential edges under the code-execution threat model.

Threat model TM1 ("code execution"): the adversary can run arbitrary code on a compute
resource. In that situation the resource's execution-role credentials are always
obtainable:

- EC2: any on-box process can complete the IMDSv2 token handshake, so the IMDS version
  is irrelevant. Enforcing IMDSv2 does NOT sever this path.
- Lambda: credentials are injected into the execution environment as variables
  (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN). No IMDS involved,
  so this path is even more direct than on EC2.

This is deliberately distinct from `metadata.discover_metadata_edges()`, which models
TM2 ("SSRF only") where the adversary can force outbound requests but cannot execute
code. IMDSv2 is effective in TM2 and only in TM2.
"""

from __future__ import annotations

import logging

from blast_radius_scanner.models import DiscoveryResult
from blast_radius_scanner.reachability.network import Edge

logger = logging.getLogger(__name__)


def discover_identity_edges(discovery: DiscoveryResult) -> list[Edge]:
    """Determine compute -> execution-role edges for the code-execution threat model.

    Unlike the metadata (SSRF) edges, these are unconditional: if a compute resource
    has a role attached and the adversary can execute code on it, they hold the role.

    Note on instance state: edges are emitted for EC2 instances in any state, not just
    "running". A stopped instance still has an instance profile, and the graph models
    potential reachability. Filtering by run state belongs to entry-point selection
    (see `entry_point_selector`), not to the edge model.
    """
    edges: list[Edge] = []

    for inst in discovery.ec2_instances:
        if not inst.iam_role_name:
            continue
        edges.append(Edge(
            source_id=inst.instance_id,
            target_id=f"iam_role:{inst.iam_role_name}",
            edge_type="identity",
            label="instance role credentials (code execution)",
            details={
                "role_name": inst.iam_role_name,
                "mechanism": "imds_on_box",
                "instance_state": inst.state,
                "imds_http_tokens": inst.imds_http_tokens,
            },
        ))

    for fn in discovery.lambda_functions:
        if not fn.role_name:
            continue
        edges.append(Edge(
            source_id=fn.function_arn,
            target_id=f"iam_role:{fn.role_name}",
            edge_type="identity",
            label="execution role credentials (code execution)",
            details={
                "role_name": fn.role_name,
                "mechanism": "execution_environment_variables",
            },
        ))

    logger.info("Discovered %d identity edges", len(edges))
    return edges
