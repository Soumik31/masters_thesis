"""Report formatter - terminal text report and JSON output."""

from __future__ import annotations

import json
import logging
from typing import Any

import networkx as nx

from blast_radius_scanner.scorer import EdgeImpact, ScoringResult

logger = logging.getLogger(__name__)

# Ordered rows for the threat model comparison table.
_THREAT_MODEL_ROWS = (
    ("code_exec", "TM1 code execution"),
    ("ssrf", "TM2 SSRF only"),
)


def format_text_report(
    scoring: ScoringResult,
    graph: nx.DiGraph,
    region: str,
    discovery=None,
    account_name: str = "",
    account_id: str = "",
    threat_model: str = "",
    threat_model_scorings: dict[str, ScoringResult] | None = None,
    control_effectiveness: dict[str, float] | None = None,
) -> str:
    """Format the scoring result as a human-readable terminal report."""
    lines: list[str] = []

    lines.append("=" * 70)
    lines.append("  BLAST RADIUS ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append("")
    if account_name or account_id:
        display = f"{account_name} ({account_id})" if account_name != account_id else account_id
        lines.append(f"  Account:            {display}")
    lines.append(f"  Region:             {region}")
    if threat_model:
        lines.append(f"  Threat Model:       {threat_model}")
    lines.append(f"  Entry Point:        {scoring.entry_point}")
    _append_entry_point_details(lines, scoring.entry_point, graph)
    lines.append("")
    lines.append(f"  Total Resources:    {scoring.total_nodes}")
    lines.append(f"  Reachable:          {scoring.reachable_nodes}")
    lines.append(f"  Blast Radius:       {scoring.blast_radius_percent:.1f}%  [{scoring.category.upper()}]")
    lines.append("")

    bar_width = 50
    filled = int(scoring.blast_radius_percent / 100 * bar_width)
    bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
    lines.append(f"  [{bar}] {scoring.blast_radius_percent:.1f}%")
    lines.append("")

    # Threat model comparison + control effectiveness
    if threat_model_scorings:
        lines.append("-" * 70)
        lines.append("  THREAT MODEL COMPARISON")
        lines.append("-" * 70)
        lines.append("    | Threat Model                    | Reachable | Total | BR%    |")
        lines.append("    |---------------------------------|-----------|-------|--------|")
        for tm_key, tm_label in _THREAT_MODEL_ROWS:
            tm_scoring = threat_model_scorings.get(tm_key)
            if tm_scoring is None:
                continue
            denominator = max(tm_scoring.total_nodes - 1, 0)
            lines.append(
                f"    | {tm_label:<31} | {tm_scoring.reachable_nodes:<9} "
                f"| {denominator:<5} | {tm_scoring.blast_radius_percent:>5.1f}% |"
            )
        lines.append("")

    if control_effectiveness:
        lines.append("  CONTROL EFFECTIVENESS  CE(c) = BR_before - BR_after")
        for control, delta in control_effectiveness.items():
            lines.append(f"    {control:<45} {delta:>7.2f} pp")
        lines.append("")

    # Reachable resources grouped by type
    lines.append("-" * 70)
    lines.append("  REACHABLE RESOURCES")
    lines.append("-" * 70)
    grouped = _group_reachable_by_type(scoring.reachable_resource_ids, graph)
    for resource_type, resources in sorted(grouped.items()):
        lines.append(f"\n  {resource_type.upper()} ({len(resources)}):")
        for res_id in resources:
            label = graph.nodes[res_id].get("label", res_id) if res_id in graph else res_id
            lines.append(f"    - {label}")

    lines.append("")

    # Edge impact analysis
    if scoring.edge_impacts:
        # Identity edges are the TM1 premise, not controls: no control can stop in-process
        # code from reading the credentials in its own execution environment. Reporting them
        # as "controls that reduce blast radius" made the threat model itself look like the
        # single most effective mitigation available.
        premise = [e for e in scoring.edge_impacts if e.edge_type == "identity"]
        controls = [e for e in scoring.edge_impacts if e.edge_type != "identity"]

        if premise:
            lines.append("-" * 70)
            lines.append("  THREAT MODEL PREMISE (not a control)")
            lines.append("-" * 70)
            for ei in premise:
                lines.append(f"    {_fmt(ei.source, graph)} -> {_fmt(ei.target, graph)}")
                lines.append(f"           {ei.label}")
                lines.append(
                    f"           Accounts for {ei.impact_delta:.1f}% of the blast radius"
                )
            lines.append("")
            lines.append("  This path is assumed by the threat model rather than mitigable.")
            lines.append("  Reduce the role's permissions to shrink what it leads to.")
            lines.append("")

        high_impacts = [e for e in controls if e.category == "high"]
        med_impacts = [e for e in controls if e.category == "medium"]
        low_impacts = [e for e in controls if e.category == "low"]

        lines.append("-" * 70)
        lines.append("  EDGE IMPACT ANALYSIS (controls that reduce blast radius)")
        lines.append("-" * 70)
        lines.append("")

        if not controls:
            lines.append("  No mitigable edges contribute to the blast radius.")
            lines.append("")

        if high_impacts:
            lines.append("  HIGH IMPACT (removing reduces BR by >20%):")
            for ei in high_impacts:
                lines.append(f"    [{ei.edge_type}] {_fmt(ei.source, graph)} -> {_fmt(ei.target, graph)}")
                lines.append(f"           Label: {ei.label}")
                lines.append(f"           Impact: -{ei.impact_delta:.1f}% (BR would be {ei.blast_radius_without:.1f}%)")
            lines.append("")

        if med_impacts:
            lines.append("  MEDIUM IMPACT (removing reduces BR by 5-20%):")
            for ei in med_impacts:
                lines.append(f"    [{ei.edge_type}] {_fmt(ei.source, graph)} -> {_fmt(ei.target, graph)}")
                lines.append(f"           Label: {ei.label}")
                lines.append(f"           Impact: -{ei.impact_delta:.1f}%")
            lines.append("")

        if low_impacts:
            lines.append(f"  LOW IMPACT ({len(low_impacts)} edges with <5% individual impact)")
            lines.append("")

    # Results table
    lines.append("-" * 70)
    lines.append("  RESULTS TABLE")
    lines.append("-" * 70)
    lines.append(_build_results_table(scoring, graph))
    lines.append("")

    # Recommendations
    lines.append("-" * 70)
    lines.append("  RECOMMENDED CONTROLS")
    lines.append("-" * 70)
    recommendations = _generate_recommendations(scoring, graph)
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"  {i}. {rec}")
    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines)


def format_json_report(
    scoring: ScoringResult,
    graph: nx.DiGraph,
    region: str,
    account_name: str = "",
    account_id: str = "",
    threat_model: str = "",
    threat_model_scorings: dict[str, ScoringResult] | None = None,
    control_effectiveness: dict[str, float] | None = None,
) -> str:
    """Format the scoring result as JSON for programmatic consumption."""
    result: dict[str, Any] = {
        "account_name": account_name,
        "account_id": account_id,
        "region": region,
        "threat_model": threat_model,
        "threat_model_results": {
            tm: {
                "reachable_nodes": s.reachable_nodes,
                "total_nodes": s.total_nodes,
                "blast_radius_percent": s.blast_radius_percent,
                "category": s.category,
            }
            for tm, s in (threat_model_scorings or {}).items()
        },
        "control_effectiveness": control_effectiveness or {},
        "entry_point": scoring.entry_point,
        "total_nodes": scoring.total_nodes,
        "reachable_nodes": scoring.reachable_nodes,
        "blast_radius_percent": scoring.blast_radius_percent,
        "category": scoring.category,
        "reachable_resources": [
            {
                "id": res_id,
                "type": graph.nodes[res_id].get("resource_type", "unknown") if res_id in graph else "unknown",
                "label": graph.nodes[res_id].get("label", res_id) if res_id in graph else res_id,
            }
            for res_id in scoring.reachable_resource_ids
        ],
        "edge_impacts": [
            {
                "source": ei.source,
                "target": ei.target,
                "edge_type": ei.edge_type,
                "label": ei.label,
                "impact_delta": ei.impact_delta,
                "blast_radius_without": ei.blast_radius_without,
                "category": ei.category,
            }
            for ei in scoring.edge_impacts
        ],
        "recommendations": _generate_recommendations(scoring, graph),
        "graph_summary": {
            "total_edges": graph.number_of_edges(),
            "total_nodes": graph.number_of_nodes(),
        },
    }
    return json.dumps(result, indent=2)


def _append_entry_point_details(lines: list[str], entry_point: str, graph: nx.DiGraph) -> None:
    if entry_point in graph:
        attrs = graph.nodes[entry_point]
        resource_type = attrs.get("resource_type", "unknown")
        label = attrs.get("label", "")
        if label and label != entry_point:
            lines.append(f"  Entry Point Name:   {label}")
        lines.append(f"  Entry Point Type:   {resource_type}")


def _fmt(node_id: str, graph: nx.DiGraph) -> str:
    if node_id in graph:
        label = graph.nodes[node_id].get("label", node_id)
        if label != node_id:
            return f"{label} ({node_id})"
    return node_id


def _group_reachable_by_type(resource_ids: list[str], graph: nx.DiGraph) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for res_id in resource_ids:
        if res_id in graph:
            resource_type = graph.nodes[res_id].get("resource_type", "unknown")
        elif res_id.startswith("s3:"):
            resource_type = "s3"
        elif res_id.startswith("dynamodb:"):
            resource_type = "dynamodb"
        elif res_id.startswith("iam_role:"):
            resource_type = "iam_role"
        else:
            resource_type = "unknown"
        grouped.setdefault(resource_type, []).append(res_id)
    return grouped


def _generate_recommendations(scoring: ScoringResult, graph: nx.DiGraph) -> list[str]:
    recommendations: list[str] = []

    has_imds = any(ei.edge_type == "metadata" for ei in scoring.edge_impacts)
    if has_imds:
        recommendations.append(
            "Enforce IMDSv2 (HttpTokens=required) on all EC2 instances to prevent SSRF-based credential theft."
        )

    has_identity = any(ei.edge_type == "identity" for ei in scoring.edge_impacts)
    if has_identity:
        recommendations.append(
            "Execution-role credentials are obtainable whenever code runs on the resource; "
            "IMDSv2 does not sever this path. Reduce the role's permissions instead (least privilege)."
        )

    iam_high = [ei for ei in scoring.edge_impacts if ei.edge_type == "iam" and ei.category in ("high", "medium")]
    if iam_high:
        recommendations.append(
            "Review IAM role policies - high-impact roles have overly broad permissions. Apply least-privilege."
        )

    has_internet = any(ei.target == "Internet" for ei in scoring.edge_impacts)
    if has_internet:
        recommendations.append(
            "Restrict outbound internet access - use VPC endpoints for AWS services, remove NAT/IGW where not required."
        )

    network_high = [ei for ei in scoring.edge_impacts if ei.edge_type == "network" and ei.category in ("high", "medium")]
    if network_high:
        recommendations.append(
            "Tighten security group rules - restrict egress to specific ports and destination SGs."
        )

    if scoring.blast_radius_percent > 50:
        recommendations.append(
            "CRITICAL: Blast radius exceeds 50%. Consider network segmentation or separate VPCs."
        )
    elif scoring.blast_radius_percent > 20:
        recommendations.append(
            "Blast radius elevated. Implement network segmentation and least privilege to reduce lateral movement."
        )

    if not recommendations:
        recommendations.append("Blast radius is within acceptable limits. Continue monitoring for drift.")

    return recommendations


def _build_results_table(scoring: ScoringResult, graph: nx.DiGraph) -> str:
    """Build a formatted results table showing per-type breakdown."""
    # Count total nodes by type
    total_by_type: dict[str, int] = {}
    for node_id, attrs in graph.nodes(data=True):
        rtype = attrs.get("resource_type", "unknown")
        total_by_type[rtype] = total_by_type.get(rtype, 0) + 1

    # Count reachable by type
    reachable_by_type: dict[str, int] = {}
    for res_id in scoring.reachable_resource_ids:
        if res_id in graph:
            rtype = graph.nodes[res_id].get("resource_type", "unknown")
        elif res_id.startswith("s3:"):
            rtype = "s3"
        elif res_id.startswith("dynamodb:"):
            rtype = "dynamodb"
        elif res_id.startswith("iam_role:"):
            rtype = "iam_role"
        else:
            rtype = "unknown"
        reachable_by_type[rtype] = reachable_by_type.get(rtype, 0) + 1

    # Friendly labels
    label_map = {
        "ec2": "EC2 Instances",
        "s3": "S3 Buckets",
        "lambda": "Lambda",
        "rds": "RDS",
        "dynamodb": "DynamoDB",
        "iam_role": "IAM Roles",
        "internet_gateway": "Internet GWs",
        "nat_gateway": "NAT Gateways",
        "vpc_endpoint": "VPC Endpoints",
        "route_table": "Route Tables",
        "external": "Internet",
        "unknown": "Other",
    }

    # Build rows (only types that have resources)
    rows: list[tuple[str, int, int, float]] = []
    total_reachable = 0
    total_all = 0

    for rtype in sorted(total_by_type.keys(), key=lambda t: reachable_by_type.get(t, 0), reverse=True):
        reachable = reachable_by_type.get(rtype, 0)
        total = total_by_type[rtype]
        pct = (reachable / total * 100) if total > 0 else 0.0
        label = label_map.get(rtype, rtype)
        rows.append((label, reachable, total, pct))
        total_reachable += reachable
        total_all += total

    total_pct = (total_reachable / total_all * 100) if total_all > 0 else 0.0

    # Format table
    lines: list[str] = []
    lines.append("    | Resource Type   | Reachable | Total | Exposure |")
    lines.append("    |----------------|-----------|-------|----------|")
    for label, reachable, total, pct in rows:
        if reachable > 0 or total > 0:
            lines.append(f"    | {label:<14} | {reachable:<9} | {total:<5} | {pct:>5.1f}%  |")
    lines.append("    |----------------|-----------|-------|----------|")
    lines.append(f"    | {'TOTAL':<14} | {total_reachable:<9} | {total_all:<5} | {total_pct:>5.1f}%  |")

    return "\n".join(lines)


def format_results_table(
    scoring: ScoringResult,
    graph: nx.DiGraph,
    discovery: DiscoveryResult,
) -> str:
    """Format a per-type breakdown table: reachable vs total."""
    # Count total resources by type from discovery
    total_by_type: dict[str, int] = {
        "EC2 Instances": len(discovery.ec2_instances),
        "S3 Buckets": len(discovery.s3_buckets),
        "Lambda": len(discovery.lambda_functions),
        "RDS": len(discovery.rds_instances),
        "DynamoDB": len(discovery.dynamodb_tables),
        "IAM Roles": len({
            inst.iam_role_name for inst in discovery.ec2_instances if inst.iam_role_name
        } | {fn.role_name for fn in discovery.lambda_functions if fn.role_name}),
        "Internet": 1,  # The Internet node
    }

    # Count reachable by type
    reachable_by_type: dict[str, int] = {k: 0 for k in total_by_type}
    type_map = {
        "ec2": "EC2 Instances",
        "s3": "S3 Buckets",
        "lambda": "Lambda",
        "rds": "RDS",
        "dynamodb": "DynamoDB",
        "iam_role": "IAM Roles",
        "external": "Internet",
    }
    for res_id in scoring.reachable_resource_ids:
        if res_id in graph:
            rtype = graph.nodes[res_id].get("resource_type", "unknown")
        elif res_id.startswith("s3:"):
            rtype = "s3"
        elif res_id.startswith("dynamodb:"):
            rtype = "dynamodb"
        elif res_id.startswith("iam_role:"):
            rtype = "iam_role"
        elif res_id == "Internet":
            rtype = "external"
        else:
            rtype = "unknown"
        friendly = type_map.get(rtype)
        if friendly and friendly in reachable_by_type:
            reachable_by_type[friendly] += 1

    lines: list[str] = []
    lines.append("-" * 70)
    lines.append("  RESULTS TABLE")
    lines.append("-" * 70)
    lines.append("  | Resource Type  | Reachable | Total | Exposure |")
    lines.append("  |----------------|-----------|-------|----------|")

    total_reachable = 0
    total_total = 0
    for rtype, total in total_by_type.items():
        if total == 0:
            continue
        reachable = reachable_by_type.get(rtype, 0)
        exposure = (reachable / total * 100) if total > 0 else 0.0
        total_reachable += reachable
        total_total += total
        lines.append(
            f"  | {rtype:<14} | {reachable:<9} | {total:<5} | {exposure:>5.1f}%  |"
        )

    lines.append("  |----------------|-----------|-------|----------|")
    overall = (total_reachable / total_total * 100) if total_total > 0 else 0.0
    lines.append(
        f"  | {'TOTAL':<14} | {total_reachable:<9} | {total_total:<5} | {overall:>5.1f}%  |"
    )
    lines.append("-" * 70)
    return "\n".join(lines)
