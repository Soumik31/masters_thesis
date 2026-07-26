"""CLI entry point for the blast-radius-scanner."""

from __future__ import annotations

import logging
import sys

import boto3
import click

from blast_radius_scanner.charts import generate_edge_impact_chart, generate_summary_chart, generate_block_diagram
from blast_radius_scanner.discovery import discover_all
from blast_radius_scanner.entry_point_selector import select_entry_point
from blast_radius_scanner.export import export_graph_gexf
from blast_radius_scanner.graph import build_attack_graph
from blast_radius_scanner.reachability import map_reachability
from blast_radius_scanner.report import format_json_report, format_text_report
from blast_radius_scanner.scorer import score_blast_radius


@click.command()
@click.option("--region", required=True, help="AWS region to scan (e.g. eu-central-1)")
@click.option("--entry-point", default=None, help="Resource ID or ARN of the entry point")
@click.option("--auto-entry-point", is_flag=True, default=False, help="Automatically select the most exposed resource as entry point")
@click.option("--all-entry-points", is_flag=True, default=False, help="Scan all compute resources as entry points and compare")
@click.option("--profile", default=None, help="AWS CLI profile name to use")
@click.option("--output", "output_format", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(
    region: str,
    entry_point: str | None,
    auto_entry_point: bool,
    all_entry_points: bool,
    profile: str | None,
    output_format: str,
    verbose: bool,
) -> None:
    """Blast Radius Scanner - measure the blast radius of AWS resources using attack graph analysis."""
    # Validate mutual exclusivity
    flags_set = sum([bool(entry_point), auto_entry_point, all_entry_points])
    if flags_set > 1:
        raise click.UsageError("--entry-point, --auto-entry-point, and --all-entry-points are mutually exclusive.")
    if flags_set == 0:
        raise click.UsageError("Provide one of: --entry-point, --auto-entry-point, or --all-entry-points.")

    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s | %(name)s | %(message)s",
        stream=sys.stderr,
    )

    # Create boto3 session
    session_kwargs: dict = {"region_name": region}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(**session_kwargs)

    # Phase 1: Discovery
    click.echo("Phase 1/4: Discovering resources...", err=True)
    discovery_result = discover_all(session, region)
    click.echo(f"  Found {discovery_result.total_resources} resources", err=True)

    # --- ALL ENTRY POINTS MODE ---
    if all_entry_points:
        _run_all_entry_points(session, discovery_result, region, output_format)
        return

    # --- AUTO ENTRY POINT MODE ---
    if auto_entry_point:
        click.echo("", err=True)
        click.echo("Entry Point Selection:", err=True)
        candidates = select_entry_point(discovery_result)

        if not candidates:
            click.echo("  No compute resources found. Cannot auto-select entry point.", err=True)
            sys.exit(1)

        for i, candidate in enumerate(candidates[:5], 1):
            reasons_str = ", ".join(candidate.reasons) if candidate.reasons else "no specific exposure"
            click.echo(
                f"  #{i} {candidate.resource_id} ({candidate.name}) — Score: {candidate.score}/100",
                err=True,
            )
            click.echo(f"      Reasons: {reasons_str}", err=True)

        entry_point = candidates[0].resource_id
        click.echo("", err=True)
        click.echo(f"  Selected: {entry_point}", err=True)
        click.echo("", err=True)

    # --- SINGLE ENTRY POINT SCAN ---
    _run_single_entry_point(session, discovery_result, entry_point, region, output_format)


def _run_single_entry_point(
    session: "boto3.Session",
    discovery_result,
    entry_point: str,
    region: str,
    output_format: str,
) -> None:
    """Run the full scan for a single entry point with all outputs saved to timestamped folder."""
    import os
    from datetime import datetime

    # Create timestamped results folder
    timestamp = datetime.now().strftime("%d%m%Y-%H%M")
    results_dir = os.path.join("results", timestamp)
    os.makedirs(results_dir, exist_ok=True)

    # Phase 2: Reachability mapping
    click.echo("Phase 2/4: Mapping reachability...", err=True)
    edges = map_reachability(session, discovery_result)
    click.echo(f"  Found {len(edges)} reachability edges", err=True)

    # Phase 3: Build attack graph
    click.echo("Phase 3/4: Building attack graph...", err=True)
    graph = build_attack_graph(discovery_result, edges)
    click.echo(f"  Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges", err=True)

    # Phase 4: Scoring
    click.echo("Phase 4/4: Calculating blast radius...", err=True)
    scoring = score_blast_radius(graph, entry_point)
    click.echo(f"  Blast radius: {scoring.blast_radius_percent:.1f}% ({scoring.category})", err=True)
    click.echo("", err=True)

    # Output report to terminal
    text_report = format_text_report(scoring, graph, region)
    click.echo(text_report)

    # Save all outputs to results folder
    # 1. Text report
    with open(os.path.join(results_dir, "report.txt"), "w") as f:
        f.write(text_report)

    # 2. JSON report
    json_report = format_json_report(scoring, graph, region)
    with open(os.path.join(results_dir, "results.json"), "w") as f:
        f.write(json_report)

    # 3. Summary chart
    generate_summary_chart(scoring, graph, os.path.join(results_dir, "blast-radius-summary.png"))

    # 4. Edge impact chart
    generate_edge_impact_chart(scoring, os.path.join(results_dir, "blast-radius-edge-impact.png"))

    # 5. Block diagram
    generate_block_diagram(scoring, graph, os.path.join(results_dir, "blast-radius-diagram.png"))

    # 6. GEXF graph export
    export_graph_gexf(graph, os.path.join(results_dir, "blast-radius-graph.gexf"))

    click.echo(f"\n✅ All results saved to: {results_dir}/", err=True)


def _run_all_entry_points(
    session: "boto3.Session",
    discovery_result,
    region: str,
    output_format: str,
) -> None:
    """Run blast radius analysis for every compute resource and compare."""
    # Collect all entry point IDs
    entry_points: list[tuple[str, str, str]] = []  # (id, name, type)

    for inst in discovery_result.ec2_instances:
        if inst.state != "running":
            continue
        entry_points.append((inst.instance_id, inst.name or inst.instance_id, "EC2"))

    for fn in discovery_result.lambda_functions:
        entry_points.append((fn.function_arn, fn.function_name, "Lambda"))

    if not entry_points:
        click.echo("No compute resources found.", err=True)
        sys.exit(1)

    click.echo(f"\nScanning all entry points ({len(entry_points)} found)...\n", err=True)

    # Reachability + graph are shared across all entry points
    click.echo("  Mapping reachability...", err=True)
    edges = map_reachability(session, discovery_result)
    click.echo(f"  Found {len(edges)} reachability edges", err=True)

    click.echo("  Building attack graph...", err=True)
    graph = build_attack_graph(discovery_result, edges)
    click.echo(f"  Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges\n", err=True)

    # Score each entry point
    results: list[tuple[str, str, str, float, str]] = []  # (id, name, type, br%, status)
    highest_br = 0.0
    highest_scoring = None

    for i, (ep_id, ep_name, ep_type) in enumerate(entry_points, 1):
        scoring = score_blast_radius(graph, ep_id)
        br = scoring.blast_radius_percent

        if br > 40:
            status = "CRITICAL"
        elif br > 20:
            status = "HIGH"
        else:
            status = "OK"

        results.append((ep_id, ep_name, ep_type, br, status))

        # Track highest for chart generation
        if br > highest_br:
            highest_br = br
            highest_scoring = scoring

        status_str = f" {status}" if status != "OK" else ""
        click.echo(f"  [{i}/{len(entry_points)}] {ep_name} ({ep_type})... {br:.1f}%{status_str}", err=True)

    # Sort by blast radius descending
    results.sort(key=lambda r: r[3], reverse=True)

    # Print comparison table
    click.echo("")
    click.echo("=" * 70)
    click.echo("  ALL ENTRY POINTS — BLAST RADIUS COMPARISON")
    click.echo("=" * 70)
    click.echo("  | #  | Entry Point                | Type   | BR%    | Status   |")
    click.echo("  |----|----------------------------|--------|--------|----------|")

    for i, (ep_id, ep_name, ep_type, br, status) in enumerate(results, 1):
        name_display = ep_name[:26] if len(ep_name) > 26 else ep_name
        click.echo(
            f"  | {i:<2} | {name_display:<26} | {ep_type:<6} | {br:>5.1f}% | {status:<8} |"
        )

    click.echo("  |----|----------------------------|--------|--------|----------|")

    critical_count = sum(1 for r in results if r[4] == "CRITICAL")
    high_count = sum(1 for r in results if r[4] == "HIGH")

    click.echo("=" * 70)
    if critical_count > 0:
        click.echo(f"  CRITICAL: {critical_count} entry point(s) exceed 40% blast radius threshold.")
    if high_count > 0:
        click.echo(f"  HIGH: {high_count} entry point(s) exceed 20% blast radius threshold.")
    if critical_count == 0 and high_count == 0:
        click.echo("  All entry points within acceptable blast radius limits.")
    click.echo("=" * 70)

    # Generate charts for the highest-risk entry point
    if highest_scoring:
        generate_summary_chart(highest_scoring, graph, "blast-radius-summary.png")
        generate_edge_impact_chart(highest_scoring, "blast-radius-edge-impact.png")
        click.echo("\nCharts saved (for highest-risk entry point): blast-radius-summary.png, blast-radius-edge-impact.png", err=True)

    # Always export graph
    export_graph_gexf(graph, "blast-radius-graph.gexf")
    click.echo("Graph exported: blast-radius-graph.gexf", err=True)
