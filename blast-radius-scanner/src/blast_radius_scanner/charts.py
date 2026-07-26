"""Chart generation — matplotlib charts for thesis-ready visualization."""

from __future__ import annotations

import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import networkx as nx

from blast_radius_scanner.scorer import ScoringResult

logger = logging.getLogger(__name__)

# Professional color palette for resource types
RESOURCE_COLORS: dict[str, str] = {
    "ec2": "#FF6B35",
    "s3": "#3CB371",
    "lambda": "#FF9F1C",
    "rds": "#4361EE",
    "dynamodb": "#7209B7",
    "iam_role": "#E63946",
    "internet_gateway": "#2EC4B6",
    "nat_gateway": "#84A98C",
    "vpc_endpoint": "#6C757D",
    "route_table": "#ADB5BD",
    "external": "#212529",
    "unknown": "#CED4DA",
}


def generate_summary_chart(
    scoring: ScoringResult,
    graph: nx.DiGraph,
    output_path: str = "blast-radius-summary.png",
) -> None:
    """Generate horizontal bar chart showing reachable resources by type."""
    # Count reachable resources by type
    type_counts: dict[str, int] = {}
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
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

    if not type_counts:
        logger.warning("No reachable resources to chart.")
        return

    # Friendly labels
    label_map = {
        "ec2": "EC2 Instances",
        "s3": "S3 Buckets",
        "lambda": "Lambda Functions",
        "rds": "RDS Instances",
        "dynamodb": "DynamoDB Tables",
        "iam_role": "IAM Roles",
        "internet_gateway": "Internet Gateways",
        "nat_gateway": "NAT Gateways",
        "vpc_endpoint": "VPC Endpoints",
        "route_table": "Route Tables",
        "external": "Internet",
        "unknown": "Other",
    }

    # Sort by count descending
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    labels = [label_map.get(t, t) for t, _ in sorted_types]
    counts = [c for _, c in sorted_types]
    colors = [RESOURCE_COLORS.get(t, "#CED4DA") for t, _ in sorted_types]

    # Entry point name
    entry_label = scoring.entry_point
    if scoring.entry_point in graph:
        entry_label = graph.nodes[scoring.entry_point].get("label", scoring.entry_point)

    # Create chart
    fig, ax = plt.subplots(figsize=(10, max(4, len(labels) * 0.6 + 1)))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    bars = ax.barh(labels, counts, color=colors, edgecolor="white", linewidth=0.5)

    # Add count labels at end of each bar
    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
            str(count), va="center", ha="left", fontsize=11, fontweight="bold",
        )

    ax.set_xlabel("Number of Reachable Resources", fontsize=12)
    ax.set_title(
        f"Blast Radius: {scoring.blast_radius_percent:.1f}% — Resources Reachable from {entry_label}",
        fontsize=13, fontweight="bold", pad=15,
    )
    ax.invert_yaxis()
    ax.set_xlim(0, max(counts) * 1.2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="y", labelsize=11)

    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    logger.info("Saved summary chart to %s", output_path)


def generate_edge_impact_chart(
    scoring: ScoringResult,
    output_path: str = "blast-radius-edge-impact.png",
) -> None:
    """Generate horizontal bar chart showing control impact ranking."""
    if not scoring.edge_impacts:
        logger.warning("No edge impacts to chart.")
        return

    # Sort by impact descending (already sorted, but be explicit)
    impacts = sorted(scoring.edge_impacts, key=lambda e: e.impact_delta, reverse=True)

    # Limit to top 15 for readability
    impacts = impacts[:15]

    labels = [ei.label or f"{ei.source} -> {ei.target}" for ei in impacts]
    deltas = [ei.impact_delta for ei in impacts]

    # Color by category
    def _get_color(category: str) -> str:
        if category == "high":
            return "#E63946"
        elif category == "medium":
            return "#FF9F1C"
        else:
            return "#FFD166"

    colors = [_get_color(ei.category) for ei in impacts]

    # Create chart
    fig, ax = plt.subplots(figsize=(10, max(4, len(labels) * 0.5 + 1)))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    bars = ax.barh(labels, deltas, color=colors, edgecolor="white", linewidth=0.5)

    # Add percentage labels
    for bar, delta in zip(bars, deltas):
        ax.text(
            bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
            f"-{delta:.1f}%", va="center", ha="left", fontsize=10,
        )

    ax.set_xlabel("Blast Radius Reduction (%)", fontsize=12)
    ax.set_title(
        "Control Impact Ranking — Blast Radius Reduction per Control",
        fontsize=13, fontweight="bold", pad=15,
    )
    ax.invert_yaxis()
    ax.set_xlim(0, max(deltas) * 1.25 if deltas else 1)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="y", labelsize=10)

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor="#E63946", label="High (>20%)"),
        Patch(facecolor="#FF9F1C", label="Medium (5-20%)"),
        Patch(facecolor="#FFD166", label="Low (<5%)"),
    ]
    ax.legend(handles=legend_elements, loc="lower right", fontsize=10)

    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    logger.info("Saved edge impact chart to %s", output_path)


def generate_block_diagram(
    scoring: ScoringResult,
    graph: nx.DiGraph,
    output_path: str = "blast-radius-diagram.png",
) -> None:
    """Generate a block diagram showing needed vs threat resources per type.

    Each box shows:
    - Resource type heading with total count
    - Needed resources (legitimate access)
    - Threat resources (excess access / blast radius)
    """
    if not scoring.reachable_resource_ids:
        logger.warning("No reachable resources to diagram.")
        return

    # Entry point info
    entry_label = scoring.entry_point
    entry_name = ""
    if scoring.entry_point in graph:
        entry_label = graph.nodes[scoring.entry_point].get("label", scoring.entry_point)
        entry_name = entry_label.lower()

    # Classify reachable resources by type with needed/threat labels
    classified = _classify_reachable_resources(scoring, graph, entry_name)

    # Filter to types that have reachable resources
    active_types = [(rtype, data) for rtype, data in classified.items() if data["needed"] or data["threats"]]
    if not active_types:
        logger.warning("No classified resources to diagram.")
        return

    # Layout: entry point on left, resource boxes on right in a grid
    num_boxes = len(active_types)
    cols = 2
    rows = (num_boxes + cols - 1) // cols

    # Calculate dynamic box heights based on item count
    line_spacing = 0.32
    box_width = 4.2
    x_spacing = 4.8
    box_heights: list[float] = []
    for _, data in active_types:
        total_items = len(data["needed"]) + len(data["threats"])
        h = 0.8 + total_items * line_spacing
        box_heights.append(h)

    # Figure height based on tallest column
    col_heights = [0.0, 0.0]
    gap = 0.6
    for idx, h in enumerate(box_heights):
        col = idx % cols
        col_heights[col] += h + gap
    tallest_col = max(col_heights)

    fig_width = 14
    fig_height = max(6, tallest_col + 3.5)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.axis("off")

    # Title
    ax.set_title(
        f"Blast Radius Breakdown: {scoring.blast_radius_percent:.1f}% — Needed vs Threat from {entry_label}",
        fontsize=13, fontweight="bold", pad=20,
    )

    # Coordinate system
    ax.set_xlim(0, fig_width)
    ax.set_ylim(0, fig_height)

    # Draw entry point box (left side, vertically centered)
    ep_x = 1.5
    ep_y = fig_height / 2
    _draw_entry_box(ax, ep_x, ep_y, entry_label, scoring.blast_radius_percent)

    # Draw resource type boxes in a grid on the right with dynamic heights
    box_start_x = 4.5
    top_y = fig_height - 1.5

    # Track current y position per column
    col_y = [top_y, top_y]

    for idx, (rtype, data) in enumerate(active_types):
        col = idx % cols
        bx = box_start_x + col * x_spacing
        by = col_y[col]
        box_h = box_heights[idx]

        _draw_resource_box(ax, bx, by, rtype, data, box_width, box_h)

        # Draw arrow from entry point to box
        ax.annotate(
            "", xy=(bx, by - box_h / 2 + 0.3),
            xytext=(ep_x + 1.0, ep_y),
            arrowprops=dict(arrowstyle="->", color="#888888", lw=1.2,
                           connectionstyle="arc3,rad=0.1"),
        )

        # Move column y down for next box
        col_y[col] -= box_h + gap

    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    logger.info("Saved block diagram to %s", output_path)


def _classify_reachable_resources(
    scoring: ScoringResult,
    graph: nx.DiGraph,
    entry_name: str,
) -> dict[str, dict]:
    """Classify each reachable resource as needed or threat.

    Returns dict: resource_type -> {"needed": [...], "threats": [...]}
    """
    classified: dict[str, dict] = {
        "S3 Buckets": {"needed": [], "threats": []},
        "RDS": {"needed": [], "threats": []},
        "Lambda": {"needed": [], "threats": []},
        "DynamoDB": {"needed": [], "threats": []},
        "Internet": {"needed": [], "threats": []},
        "IAM Roles": {"needed": [], "threats": []},
    }

    for res_id in scoring.reachable_resource_ids:
        # Determine type and label
        if res_id in graph:
            rtype = graph.nodes[res_id].get("resource_type", "unknown")
            label = graph.nodes[res_id].get("label", res_id)
        elif res_id.startswith("s3:"):
            rtype = "s3"
            label = res_id.split(":", 1)[1]
        elif res_id.startswith("dynamodb:"):
            rtype = "dynamodb"
            label = res_id.split(":", 1)[1]
        elif res_id.startswith("iam_role:"):
            rtype = "iam_role"
            label = res_id.split(":", 1)[1]
        elif res_id == "Internet":
            rtype = "external"
            label = "Internet"
        else:
            continue

        # Classify as needed or threat
        is_needed = _is_needed(rtype, label, entry_name)

        # Map to display category
        category_map = {
            "s3": "S3 Buckets",
            "rds": "RDS",
            "lambda": "Lambda",
            "dynamodb": "DynamoDB",
            "external": "Internet",
            "iam_role": "IAM Roles",
        }
        category = category_map.get(rtype)
        if not category:
            continue

        if is_needed:
            classified[category]["needed"].append(label)
        else:
            classified[category]["threats"].append(label)

    return classified


def _is_needed(resource_type: str, label: str, entry_name: str) -> bool:
    """Determine if a resource is legitimately needed by the entry point.

    Heuristics:
    - S3: bucket name contains "media" -> needed
    - RDS: name does NOT contain "backup" or "restored" -> needed (primary DB)
    - Lambda: only if function name matches entry point stack name
    - DynamoDB: only if table name relates to entry point
    - Internet: never needed (always threat/exfiltration path)
    - IAM Role: never classified as needed (it's the mechanism)
    """
    label_lower = label.lower()

    if resource_type == "s3":
        return "media" in label_lower

    if resource_type == "rds":
        if "backup" in label_lower or "restored" in label_lower or "replica" in label_lower:
            return False
        return True  # Primary DB is needed

    if resource_type == "lambda":
        # Only needed if function name shares stack prefix with entry point
        if entry_name:
            # Extract stack prefix (e.g., "wordpressstack" from "WordpressStack/MyInstance")
            stack_prefix = entry_name.split("/")[0].split("-")[0].lower()
            if stack_prefix and len(stack_prefix) > 3 and stack_prefix in label_lower:
                return True
        return False

    if resource_type == "dynamodb":
        # Only needed if table name relates to entry point
        if entry_name:
            stack_prefix = entry_name.split("/")[0].split("-")[0].lower()
            if stack_prefix and len(stack_prefix) > 3 and stack_prefix in label_lower:
                return True
        return False

    if resource_type == "external":
        return False  # Internet access is always a threat (exfiltration)

    if resource_type == "iam_role":
        return False  # Credential theft path, not a legitimate target

    return False


def _draw_entry_box(ax, x: float, y: float, label: str, br_percent: float) -> None:
    """Draw the entry point box."""
    from matplotlib.patches import FancyBboxPatch

    box = FancyBboxPatch(
        (x - 1.0, y - 0.6), 2.0, 1.2,
        boxstyle="round,pad=0.15",
        facecolor="#FF6B35", edgecolor="#CC4400", linewidth=2,
    )
    ax.add_patch(box)

    # Truncate label if too long
    display = label if len(label) <= 18 else label[:15] + "..."
    ax.text(x, y + 0.15, display, ha="center", va="center",
            fontsize=9, fontweight="bold", color="white")
    ax.text(x, y - 0.25, f"BR: {br_percent:.1f}%", ha="center", va="center",
            fontsize=8, color="white")


def _draw_resource_box(
    ax, x: float, y: float, rtype: str, data: dict,
    width: float, height: float,
) -> None:
    """Draw a resource type box with needed/threat breakdown. Shows ALL items."""
    from matplotlib.patches import FancyBboxPatch

    total = len(data["needed"]) + len(data["threats"])
    needed_count = len(data["needed"])
    threat_count = len(data["threats"])

    # Box background color based on threat ratio
    if threat_count == 0:
        bg_color = "#E8F5E9"
        border_color = "#4CAF50"
    elif needed_count == 0:
        bg_color = "#FFEBEE"
        border_color = "#E53935"
    else:
        bg_color = "#FFF8E1"
        border_color = "#FF8F00"

    box = FancyBboxPatch(
        (x - 0.1, y - height + 0.3), width, height,
        boxstyle="round,pad=0.1",
        facecolor=bg_color, edgecolor=border_color, linewidth=1.5,
    )
    ax.add_patch(box)

    # Title line
    title = f"{rtype} ({total})"
    ax.text(x + width / 2 - 0.1, y - 0.05, title,
            ha="center", va="top", fontsize=10, fontweight="bold", color="#333333")

    # Content lines — show ALL items, no truncation
    line_y = y - 0.45
    line_spacing = 0.32

    # Show all needed items
    for item in data["needed"]:
        ax.text(x + 0.1, line_y, f"\u2705 {item} (needed)",
                ha="left", va="top", fontsize=7.5, color="#2E7D32")
        line_y -= line_spacing

    # Show all threat items
    for item in data["threats"]:
        ax.text(x + 0.1, line_y, f"\U0001F6A8 {item} (THREAT)",
                ha="left", va="top", fontsize=7.5, color="#C62828")
        line_y -= line_spacing
