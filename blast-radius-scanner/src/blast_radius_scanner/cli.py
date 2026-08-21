"""CLI entry point for the blast-radius-scanner."""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime

import boto3
import click
import networkx as nx

from blast_radius_scanner.charts import (
    generate_block_diagram,
    generate_edge_impact_chart,
    generate_summary_chart,
)
from blast_radius_scanner.discovery import discover_all
from blast_radius_scanner.entry_point_selector import select_entry_point
from blast_radius_scanner.export import export_graph_gexf
from blast_radius_scanner.graph import build_attack_graph
from blast_radius_scanner.reachability import (
    THREAT_MODEL_LABELS,
    TM_CODE_EXEC,
    TM_SSRF,
    map_reachability_all,
)
from blast_radius_scanner.report import format_json_report, format_text_report
from blast_radius_scanner.scorer import ScoringResult, score_blast_radius

# Maps the CLI flag spelling to the internal threat model key.
_TM_FLAG_TO_KEY = {"code-exec": TM_CODE_EXEC, "ssrf": TM_SSRF}


@click.command()
@click.option("--region", required=True, help="AWS region to scan (e.g. eu-central-1)")
@click.option("--entry-point", default=None, help="Resource ID or ARN of the entry point")
@click.option("--auto-entry-point", is_flag=True, default=False, help="Automatically select the most exposed resource as entry point")
@click.option("--all-entry-points", is_flag=True, default=False, help="Scan all compute resources as entry points and compare")
@click.option("--threat-model", type=click.Choice(["code-exec", "ssrf"]), default="code-exec", help="Primary threat model for the detailed report. Both are always reported side by side.")
@click.option("--include-stopped", is_flag=True, default=False, help="Include EC2 instances that are not running as entry point candidates")
@click.option("--profile", default=None, help="AWS CLI profile name to use")
@click.option("--output", "output_format", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(
    region: str,
    entry_point: str | None,
    auto_entry_point: bool,
    all_entry_points: bool,
    threat_model: str,
    include_stopped: bool,
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

    primary_tm = _TM_FLAG_TO_KEY[threat_model]

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

    account_name, account_id = _get_account_identity(session)
    click.echo(f"  Account:  {account_name} ({account_id})", err=True)
    click.echo(f"  Threat model (primary): {THREAT_MODEL_LABELS[primary_tm]}", err=True)
    click.echo("", err=True)

    # Phase 1: Discovery
    click.echo("Phase 1/4: Discovering resources...", err=True)
    discovery_result = discover_all(session, region)
    click.echo(f"  Found {discovery_result.total_resources} resources", err=True)

    # Phase 2: Reachability mapping for every threat model (single IAM pass)
    click.echo("Phase 2/4: Mapping reachability...", err=True)
    edge_sets = map_reachability_all(session, discovery_result)
    for tm, edges in edge_sets.items():
        click.echo(f"  {tm}: {len(edges)} edges", err=True)

    # Phase 3: Build one graph per threat model, plus the IMDSv2 counterfactual
    click.echo("Phase 3/4: Building attack graphs...", err=True)
    graphs: dict[str, nx.DiGraph] = {
        tm: build_attack_graph(discovery_result, edges) for tm, edges in edge_sets.items()
    }
    # Counterfactual: same threat model, IMDS credential-theft edges severed
    hardened_graphs: dict[str, nx.DiGraph] = {
        tm: build_attack_graph(
            discovery_result, [e for e in edges if e.edge_type != "metadata"]
        )
        for tm, edges in edge_sets.items()
    }
    primary_graph = graphs[primary_tm]
    click.echo(
        f"  {primary_tm} graph: {primary_graph.number_of_nodes()} nodes, "
        f"{primary_graph.number_of_edges()} edges",
        err=True,
    )

    # --- ALL ENTRY POINTS MODE ---
    if all_entry_points:
        _run_all_entry_points(
            discovery_result, graphs, primary_tm, include_stopped, region
        )
        return

    # --- AUTO ENTRY POINT MODE ---
    if auto_entry_point:
        click.echo("", err=True)
        click.echo("Entry Point Selection:", err=True)
        candidates = select_entry_point(
            discovery_result,
            edges=edge_sets[primary_tm],
            include_stopped=include_stopped,
        )

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
    _run_single_entry_point(
        discovery_result,
        graphs,
        hardened_graphs,
        primary_tm,
        entry_point,
        region,
        account_name,
        account_id,
    )


def _get_account_identity(session: boto3.Session) -> tuple[str, str]:
    """Return (account_name, account_id). Falls back to the ID when no alias is set."""
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    try:
        iam = session.client("iam")
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        account_name = aliases[0] if aliases else account_id
    except Exception:
        account_name = account_id
    return account_name, account_id


def _run_single_entry_point(
    discovery_result,
    graphs: dict[str, nx.DiGraph],
    hardened_graphs: dict[str, nx.DiGraph],
    primary_tm: str,
    entry_point: str,
    region: str,
    account_name: str,
    account_id: str,
) -> None:
    """Score one entry point under every threat model and save all outputs."""
    timestamp = datetime.now().strftime("%d%m%Y-%H%M")
    results_dir = os.path.join("results", timestamp)
    os.makedirs(results_dir, exist_ok=True)

    # Phase 4: Scoring under each threat model
    click.echo("Phase 4/4: Calculating blast radius...", err=True)
    scorings: dict[str, ScoringResult] = {
        tm: score_blast_radius(graph, entry_point) for tm, graph in graphs.items()
    }
    for tm, scoring in scorings.items():
        click.echo(
            f"  {tm}: {scoring.blast_radius_percent:.1f}% ({scoring.category})", err=True
        )

    # Control effectiveness of IMDSv2, measured within each threat model
    control_effectiveness: dict[str, float] = {}
    for tm, graph in graphs.items():
        before = scorings[tm].blast_radius_percent
        after = score_blast_radius(hardened_graphs[tm], entry_point).blast_radius_percent
        control_effectiveness[f"CE(IMDSv2) within {tm}"] = round(before - after, 2)
    click.echo("", err=True)

    scoring = scorings[primary_tm]
    graph = graphs[primary_tm]

    text_report = format_text_report(
        scoring,
        graph,
        region,
        account_name=account_name,
        account_id=account_id,
        threat_model=THREAT_MODEL_LABELS[primary_tm],
        threat_model_scorings=scorings,
        control_effectiveness=control_effectiveness,
    )
    click.echo(text_report)

    with open(os.path.join(results_dir, "report.txt"), "w") as f:
        f.write(text_report)

    json_report = format_json_report(
        scoring,
        graph,
        region,
        account_name=account_name,
        account_id=account_id,
        threat_model=primary_tm,
        threat_model_scorings=scorings,
        control_effectiveness=control_effectiveness,
    )
    with open(os.path.join(results_dir, "results.json"), "w") as f:
        f.write(json_report)

    generate_summary_chart(scoring, graph, os.path.join(results_dir, "blast-radius-summary.png"))
    generate_edge_impact_chart(scoring, os.path.join(results_dir, "blast-radius-edge-impact.png"))
    generate_block_diagram(scoring, graph, os.path.join(results_dir, "blast-radius-diagram.png"))
    export_graph_gexf(graph, os.path.join(results_dir, "blast-radius-graph.gexf"))

    click.echo(f"\n✅ All results saved to: {results_dir}/", err=True)


def _run_all_entry_points(
    discovery_result,
    graphs: dict[str, nx.DiGraph],
    primary_tm: str,
    include_stopped: bool,
    region: str,
) -> None:
    """Run blast radius analysis for every compute resource and compare."""
    entry_points: list[tuple[str, str, str]] = []  # (id, name, type)

    for inst in discovery_result.ec2_instances:
        if inst.state != "running" and not include_stopped:
            continue
        entry_points.append((inst.instance_id, inst.name or inst.instance_id, "EC2"))

    for fn in discovery_result.lambda_functions:
        entry_points.append((fn.function_arn, fn.function_name, "Lambda"))

    if not entry_points:
        click.echo("No compute resources found.", err=True)
        sys.exit(1)

    click.echo(f"\nScanning all entry points ({len(entry_points)} found)...\n", err=True)

    graph = graphs[primary_tm]

    results: list[tuple[str, str, str, float, float, str]] = []
    highest_br = -1.0
    highest_scoring = None

    for i, (ep_id, ep_name, ep_type) in enumerate(entry_points, 1):
        primary_scoring = score_blast_radius(graph, ep_id)
        br = primary_scoring.blast_radius_percent
        other_tm = TM_SSRF if primary_tm == TM_CODE_EXEC else TM_CODE_EXEC
        br_other = score_blast_radius(graphs[other_tm], ep_id).blast_radius_percent

        if br > 40:
            status = "CRITICAL"
        elif br > 20:
            status = "HIGH"
        else:
            status = "OK"

        results.append((ep_id, ep_name, ep_type, br, br_other, status))

        if br > highest_br:
            highest_br = br
            highest_scoring = primary_scoring

        status_str = f" {status}" if status != "OK" else ""
        click.echo(f"  [{i}/{len(entry_points)}] {ep_name} ({ep_type})... {br:.1f}%{status_str}", err=True)

    results.sort(key=lambda r: r[3], reverse=True)

    other_tm = TM_SSRF if primary_tm == TM_CODE_EXEC else TM_CODE_EXEC
    primary_header = "TM1 BR%" if primary_tm == TM_CODE_EXEC else "TM2 BR%"
    other_header = "TM2 BR%" if primary_tm == TM_CODE_EXEC else "TM1 BR%"

    click.echo("")
    click.echo("=" * 78)
    click.echo("  ALL ENTRY POINTS — BLAST RADIUS COMPARISON")
    click.echo("=" * 78)
    click.echo(f"  | #  | Entry Point                | Type   | {primary_header:<8}| {other_header:<8}| Status   |")
    click.echo("  |----|----------------------------|--------|---------|---------|----------|")

    for i, (ep_id, ep_name, ep_type, br, br_other, status) in enumerate(results, 1):
        name_display = ep_name[:26] if len(ep_name) > 26 else ep_name
        click.echo(
            f"  | {i:<2} | {name_display:<26} | {ep_type:<6} | {br:>6.1f}% | {br_other:>6.1f}% | {status:<8} |"
        )

    click.echo("  |----|----------------------------|--------|---------|---------|----------|")

    critical_count = sum(1 for r in results if r[5] == "CRITICAL")
    high_count = sum(1 for r in results if r[5] == "HIGH")

    click.echo("=" * 78)
    click.echo(f"  Primary threat model: {THREAT_MODEL_LABELS[primary_tm]}")
    click.echo(f"  Comparison column:    {THREAT_MODEL_LABELS[other_tm]}")
    if critical_count > 0:
        click.echo(f"  CRITICAL: {critical_count} entry point(s) exceed 40% blast radius threshold.")
    if high_count > 0:
        click.echo(f"  HIGH: {high_count} entry point(s) exceed 20% blast radius threshold.")
    if critical_count == 0 and high_count == 0:
        click.echo("  All entry points within acceptable blast radius limits.")
    click.echo("=" * 78)

    if highest_scoring:
        generate_summary_chart(highest_scoring, graph, "blast-radius-summary.png")
        generate_edge_impact_chart(highest_scoring, "blast-radius-edge-impact.png")
        click.echo("\nCharts saved (for highest-risk entry point): blast-radius-summary.png, blast-radius-edge-impact.png", err=True)

    export_graph_gexf(graph, "blast-radius-graph.gexf")
    click.echo("Graph exported: blast-radius-graph.gexf", err=True)
