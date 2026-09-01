"""CLI entry point for the blast-radius-scanner."""

from __future__ import annotations

import json
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

logger = logging.getLogger(__name__)

# Maps the CLI flag spelling to the internal threat model key.
_TM_FLAG_TO_KEY = {"code-exec": TM_CODE_EXEC, "ssrf": TM_SSRF}


@click.command()
@click.option("--region", required=True, help="AWS region to scan (e.g. eu-central-1)")
@click.option("--entry-point", default=None, help="Resource ID or ARN of the entry point")
@click.option("--auto-entry-point", is_flag=True, default=False, help="Automatically select the most exposed resource as entry point")
@click.option("--all-entry-points", is_flag=True, default=False, help="Scan all compute resources as entry points and compare")
@click.option("--threat-model", type=click.Choice(["code-exec", "ssrf"]), default="code-exec", help="Primary threat model for the detailed report. Both are always reported side by side.")
@click.option("--include-stopped", is_flag=True, default=False, help="Include EC2 instances that are not running as entry point candidates")
@click.option("--exposed-only", is_flag=True, default=False, help="Only consider entry points an untrusted caller can reach without AWS credentials (public IP, public Function URL, or wildcard invoke policy)")
@click.option("--profile", default=None, help="AWS CLI profile name to use")
@click.option("--account-name", default=None, help="Label for this account in the report, e.g. \"WordPress prod\". Overrides the IAM alias and Organizations name.")
@click.option("--output", "output_format", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(
    region: str,
    entry_point: str | None,
    auto_entry_point: bool,
    all_entry_points: bool,
    threat_model: str,
    include_stopped: bool,
    exposed_only: bool,
    profile: str | None,
    account_name: str | None,
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

    account_name, account_id = _get_account_identity(session, account_name)
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
            discovery_result, graphs, primary_tm, include_stopped, exposed_only,
            edge_sets[primary_tm], region
        )
        return

    # --- AUTO ENTRY POINT MODE ---
    if auto_entry_point:
        click.echo("", err=True)
        scope = "externally reachable only" if exposed_only else "all compute resources"
        click.echo(f"Entry Point Selection ({scope}):", err=True)
        candidates = select_entry_point(
            discovery_result,
            edges=edge_sets[primary_tm],
            include_stopped=include_stopped,
            exposed_only=exposed_only,
        )

        if not candidates:
            if exposed_only:
                _write_no_exposure_result(
                    discovery_result,
                    graphs[primary_tm],
                    primary_tm,
                    region,
                    account_name,
                    account_id,
                    edge_sets,
                )
            else:
                click.echo("  No compute resources found. Cannot auto-select entry point.", err=True)
            sys.exit(1)

        if not exposed_only:
            reachable = sum(1 for c in candidates if c.is_externally_reachable)
            click.echo(
                f"  Note: {reachable}/{len(candidates)} candidates are externally reachable. "
                "Others require prior account access to reach.",
                err=True,
            )

        for i, candidate in enumerate(candidates[:5], 1):
            reasons_str = ", ".join(candidate.reasons) if candidate.reasons else "no specific exposure"
            marker = "external" if candidate.is_externally_reachable else "internal"
            click.echo(
                f"  #{i} [{marker}] {candidate.resource_id} ({candidate.name}) — Score: {candidate.score}/100",
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


# Account metadata parameters written by AWS Account Factory for Terraform. These are read
# by exact name only. Unlike the bulk secret and parameter discovery, which deliberately
# reads metadata and never values, these specific paths hold non-secret account labels
# (an application name and environment), so reading their values is safe and is the only
# way to name a member account automatically. No other parameter value is ever read.
_AFT_NAME_PARAMETERS = (
    "/aft/account-request/custom-fields/appName",
    "/aft/account-request/custom-fields/appEnv",
)


def _aft_account_name(session: boto3.Session) -> str | None:
    """Build an account label from AFT metadata parameters, e.g. "wordpress-prod"."""
    try:
        client = session.client("ssm")
        parts: list[str] = []
        for name in _AFT_NAME_PARAMETERS:
            try:
                value = client.get_parameter(Name=name)["Parameter"]["Value"]
            except Exception:
                continue
            value = (value or "").strip()
            if value:
                parts.append(value)
        if parts:
            return "-".join(parts)
    except Exception as e:
        logger.debug("Could not read AFT account metadata: %s", e)
    return None


def _get_account_identity(
    session: boto3.Session, override: str | None = None
) -> tuple[str, str]:
    """Return (account_name, account_id).

    Resolution order, each falling through to the next:
      1. --account-name, when given.
      2. The IAM account alias.
      3. The Organizations account name. Only works from the management account or a
         delegated administrator; member accounts are denied.
      4. AFT account metadata parameters, which is what actually resolves for Control
         Tower member accounts where no alias is set.
      5. The account ID.
    """
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    if override:
        return override, account_id

    try:
        aliases = session.client("iam").list_account_aliases().get("AccountAliases", [])
        if aliases:
            return aliases[0], account_id
    except Exception as e:
        logger.debug("Could not list account aliases: %s", e)

    try:
        account = session.client("organizations").describe_account(AccountId=account_id)
        name = account.get("Account", {}).get("Name")
        if name:
            return name, account_id
    except Exception as e:
        logger.debug(
            "Could not describe account via Organizations (expected from a member "
            "account): %s",
            e,
        )

    aft_name = _aft_account_name(session)
    if aft_name:
        return aft_name, account_id

    logger.info(
        "No account alias, Organizations name or AFT metadata available; using the account "
        "ID. Pass --account-name to label this account explicitly."
    )
    return account_id, account_id


def _write_no_exposure_result(
    discovery_result,
    graph: nx.DiGraph,
    primary_tm: str,
    region: str,
    account_name: str,
    account_id: str,
    edge_sets: dict[str, list],
) -> None:
    """Record a scan that found no externally reachable entry point.

    "No unauthenticated entry point exists in this account" is a finding, not a failure, so
    it needs to leave evidence behind. Previously the run exited before creating the results
    directory, discarding all the discovery and graph work.
    """
    timestamp = datetime.now().strftime("%d%m%Y-%H%M")
    results_dir = os.path.join("results", timestamp)
    os.makedirs(results_dir, exist_ok=True)

    lambda_total = len(discovery_result.lambda_functions)
    ec2_total = len(discovery_result.ec2_instances)
    with_any_signal = sum(1 for fn in discovery_result.lambda_functions if fn.exposures)
    with_any_signal += sum(1 for i in discovery_result.ec2_instances if i.exposures or i.public_ip)

    lines = [
        "=" * 70,
        "  BLAST RADIUS ANALYSIS REPORT",
        "=" * 70,
        "",
        f"  Account:            {account_name} ({account_id})"
        if account_name != account_id
        else f"  Account:            {account_id}",
        f"  Region:             {region}",
        f"  Threat Model:       {THREAT_MODEL_LABELS[primary_tm]}",
        "  Entry Point Scope:  externally reachable only",
        "",
        "  RESULT: no externally reachable entry point found.",
        "",
        "  No EC2 instance or Lambda function in this account can be reached by an",
        "  unauthenticated caller. Reaching any compute resource here would first require",
        "  obtaining AWS credentials, so blast radius from an external attacker is 0%.",
        "",
        f"  Compute resources examined:   {ec2_total} EC2, {lambda_total} Lambda",
        f"  With any exposure signal:     {with_any_signal}",
        f"  Graph ({primary_tm}):         {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges",
        "",
        "  Edge counts per threat model:",
    ]
    for tm, edges in edge_sets.items():
        lines.append(f"    {tm}: {len(edges)} edges")
    lines += [
        "",
        "  Note: this does not mean the roles are tightly scoped. Re-run without",
        "  --exposed-only to measure the latent blast radius that would apply if any",
        "  resource were compromised by other means.",
        "",
        "=" * 70,
    ]
    report = "\n".join(lines)

    with open(os.path.join(results_dir, "report.txt"), "w") as f:
        f.write(report)

    summary = {
        "account_name": account_name,
        "account_id": account_id,
        "region": region,
        "threat_model": primary_tm,
        "entry_point_scope": "exposed_only",
        "externally_reachable_entry_points": 0,
        "blast_radius_percent": 0.0,
        "ec2_instances": ec2_total,
        "lambda_functions": lambda_total,
        "resources_with_exposure_signal": with_any_signal,
        "graph_summary": {
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
        },
        "edge_counts": {tm: len(edges) for tm, edges in edge_sets.items()},
    }
    with open(os.path.join(results_dir, "results.json"), "w") as f:
        json.dump(summary, f, indent=2)

    export_graph_gexf(graph, os.path.join(results_dir, "blast-radius-graph.gexf"))

    click.echo(report)
    click.echo(f"\nNo externally reachable entry point. Findings saved to: {results_dir}/", err=True)


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
    exposed_only: bool,
    edges: list,
    region: str,
) -> None:
    """Run blast radius analysis for every compute resource and compare."""
    # Use the selector so exposure and stopped-state filtering behave identically to
    # auto mode, rather than being re-implemented here.
    candidates = select_entry_point(
        discovery_result,
        edges=edges,
        include_stopped=include_stopped,
        exposed_only=exposed_only,
    )
    entry_points: list[tuple[str, str, str, bool]] = [
        (
            c.resource_id,
            c.name,
            "EC2" if c.resource_type == "ec2" else "Lambda",
            c.is_externally_reachable,
        )
        for c in candidates
    ]

    if not entry_points:
        if exposed_only:
            click.echo(
                "No externally reachable entry points found. Re-run without --exposed-only "
                "to measure worst-case spread from an assumed internal compromise.",
                err=True,
            )
        else:
            click.echo("No compute resources found.", err=True)
        sys.exit(1)

    scope = "externally reachable only" if exposed_only else "all compute resources"
    click.echo(f"\nScanning entry points ({len(entry_points)} found, {scope})...\n", err=True)

    graph = graphs[primary_tm]

    results: list[tuple[str, str, str, float, float, str, bool]] = []
    highest_br = -1.0
    highest_scoring = None
    other_tm = TM_SSRF if primary_tm == TM_CODE_EXEC else TM_CODE_EXEC

    for i, (ep_id, ep_name, ep_type, external) in enumerate(entry_points, 1):
        primary_scoring = score_blast_radius(graph, ep_id)
        br = primary_scoring.blast_radius_percent
        br_other = score_blast_radius(graphs[other_tm], ep_id).blast_radius_percent

        if br > 40:
            status = "CRITICAL"
        elif br > 20:
            status = "HIGH"
        else:
            status = "OK"

        results.append((ep_id, ep_name, ep_type, br, br_other, status, external))

        if br > highest_br:
            highest_br = br
            highest_scoring = primary_scoring

        status_str = f" {status}" if status != "OK" else ""
        click.echo(f"  [{i}/{len(entry_points)}] {ep_name} ({ep_type})... {br:.1f}%{status_str}", err=True)

    results.sort(key=lambda r: r[3], reverse=True)

    primary_header = "TM1 BR%" if primary_tm == TM_CODE_EXEC else "TM2 BR%"
    other_header = "TM2 BR%" if primary_tm == TM_CODE_EXEC else "TM1 BR%"

    click.echo("")
    click.echo("=" * 90)
    click.echo("  ALL ENTRY POINTS — BLAST RADIUS COMPARISON")
    click.echo("=" * 90)
    click.echo(f"  | #  | Entry Point                | Type   | Reach    | {primary_header:<8}| {other_header:<8}| Status   |")
    click.echo("  |----|----------------------------|--------|----------|---------|---------|----------|")

    for i, (ep_id, ep_name, ep_type, br, br_other, status, external) in enumerate(results, 1):
        name_display = ep_name[:26] if len(ep_name) > 26 else ep_name
        reach = "external" if external else "internal"
        click.echo(
            f"  | {i:<2} | {name_display:<26} | {ep_type:<6} | {reach:<8} | {br:>6.1f}% | {br_other:>6.1f}% | {status:<8} |"
        )

    click.echo("  |----|----------------------------|--------|----------|---------|---------|----------|")

    critical_count = sum(1 for r in results if r[5] == "CRITICAL")
    high_count = sum(1 for r in results if r[5] == "HIGH")
    external_count = sum(1 for r in results if r[6])

    click.echo("=" * 90)
    click.echo(f"  Primary threat model: {THREAT_MODEL_LABELS[primary_tm]}")
    click.echo(f"  Comparison column:    {THREAT_MODEL_LABELS[other_tm]}")
    click.echo(f"  Externally reachable: {external_count}/{len(results)} entry points")
    if critical_count > 0:
        click.echo(f"  CRITICAL: {critical_count} entry point(s) exceed 40% blast radius threshold.")
    if high_count > 0:
        click.echo(f"  HIGH: {high_count} entry point(s) exceed 20% blast radius threshold.")
    if critical_count == 0 and high_count == 0:
        click.echo("  All entry points within acceptable blast radius limits.")
    click.echo("=" * 90)

    if highest_scoring:
        generate_summary_chart(highest_scoring, graph, "blast-radius-summary.png")
        generate_edge_impact_chart(highest_scoring, "blast-radius-edge-impact.png")
        click.echo("\nCharts saved (for highest-risk entry point): blast-radius-summary.png, blast-radius-edge-impact.png", err=True)

    export_graph_gexf(graph, "blast-radius-graph.gexf")
    click.echo("Graph exported: blast-radius-graph.gexf", err=True)
