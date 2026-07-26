"""Scorer - BFS from entry point, blast radius percentage, per-edge impact analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class EdgeImpact:
    """The impact of removing a single edge on the blast radius."""

    source: str
    target: str
    edge_type: str
    label: str
    blast_radius_without: float
    impact_delta: float
    category: str  # "high", "medium", "low"


@dataclass
class ScoringResult:
    """Complete scoring output for a given entry point."""

    entry_point: str
    total_nodes: int
    reachable_nodes: int
    blast_radius_percent: float
    reachable_resource_ids: list[str] = field(default_factory=list)
    edge_impacts: list[EdgeImpact] = field(default_factory=list)

    @property
    def category(self) -> str:
        if self.blast_radius_percent > 50:
            return "critical"
        elif self.blast_radius_percent > 20:
            return "high"
        elif self.blast_radius_percent > 5:
            return "medium"
        else:
            return "low"


def score_blast_radius(
    graph: nx.DiGraph,
    entry_point: str,
) -> ScoringResult:
    """Calculate blast radius from a given entry point using BFS.

    Blast Radius % = |reachable nodes from entry_point| / |total nodes - 1|
    """
    if entry_point not in graph:
        entry_point = _resolve_entry_point(graph, entry_point)

    total_nodes = graph.number_of_nodes()
    if total_nodes <= 1:
        return ScoringResult(
            entry_point=entry_point,
            total_nodes=total_nodes,
            reachable_nodes=0,
            blast_radius_percent=0.0,
        )

    reachable = _bfs_reachable(graph, entry_point)
    reachable_count = len(reachable)
    denominator = total_nodes - 1
    blast_radius = (reachable_count / denominator) * 100 if denominator > 0 else 0.0

    logger.info(
        "Entry point %s: %d/%d reachable (%.1f%%)",
        entry_point, reachable_count, denominator, blast_radius,
    )

    edge_impacts = _calculate_edge_impacts(graph, entry_point, reachable_count, denominator)

    return ScoringResult(
        entry_point=entry_point,
        total_nodes=total_nodes,
        reachable_nodes=reachable_count,
        blast_radius_percent=round(blast_radius, 2),
        reachable_resource_ids=sorted(reachable),
        edge_impacts=edge_impacts,
    )


def _resolve_entry_point(graph: nx.DiGraph, entry_point: str) -> str:
    """Try to resolve an entry point string to a node in the graph."""
    if entry_point in graph:
        return entry_point

    for node_id, attrs in graph.nodes(data=True):
        if attrs.get("resource_id") == entry_point:
            return node_id
        if attrs.get("resource_type") == "lambda" and entry_point in node_id:
            return node_id

    logger.warning("Entry point '%s' not found in graph", entry_point)
    return entry_point


def _bfs_reachable(graph: nx.DiGraph, source: str) -> set[str]:
    """BFS from source, return all reachable node IDs (excluding source)."""
    if source not in graph:
        return set()
    return nx.descendants(graph, source)


def _calculate_edge_impacts(
    graph: nx.DiGraph,
    entry_point: str,
    baseline_reachable: int,
    denominator: int,
) -> list[EdgeImpact]:
    """For each edge reachable from entry point, calculate impact of removing it."""
    if denominator == 0:
        return []

    baseline_percent = (baseline_reachable / denominator) * 100
    reachable_edges = _get_reachable_edges(graph, entry_point)
    impacts: list[EdgeImpact] = []

    for u, v, data in reachable_edges:
        graph.remove_edge(u, v)
        new_reachable = len(_bfs_reachable(graph, entry_point))
        new_percent = (new_reachable / denominator) * 100
        graph.add_edge(u, v, **data)

        delta = baseline_percent - new_percent

        if delta > 0:
            category = "high" if delta > 20 else "medium" if delta > 5 else "low"
            impacts.append(EdgeImpact(
                source=u,
                target=v,
                edge_type=data.get("edge_type", "unknown"),
                label=data.get("label", ""),
                blast_radius_without=round(new_percent, 2),
                impact_delta=round(delta, 2),
                category=category,
            ))

    impacts.sort(key=lambda e: e.impact_delta, reverse=True)
    return impacts


def _get_reachable_edges(graph: nx.DiGraph, entry_point: str) -> list[tuple]:
    """Get all edges on paths reachable from entry point."""
    if entry_point not in graph:
        return []

    reachable = _bfs_reachable(graph, entry_point)
    reachable_with_source = reachable | {entry_point}

    edges = []
    for u, v, data in graph.edges(data=True):
        if u in reachable_with_source and v in reachable_with_source:
            edges.append((u, v, data))

    return edges
