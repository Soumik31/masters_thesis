"""Graph export - export attack graph to GEXF format for visualization in Gephi."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import networkx as nx

logger = logging.getLogger(__name__)


def export_graph_gexf(graph: nx.DiGraph, output_path: str) -> None:
    """Export the attack graph to GEXF format for visualization in Gephi."""
    export_graph = _prepare_graph_for_export(graph)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    nx.write_gexf(export_graph, str(output_file))
    logger.info("Exported graph to %s (%d nodes, %d edges)",
                output_path, graph.number_of_nodes(), graph.number_of_edges())


def _prepare_graph_for_export(graph: nx.DiGraph) -> nx.DiGraph:
    """Prepare graph for GEXF export by converting all attributes to strings."""
    export_graph = nx.DiGraph()

    for node_id, attrs in graph.nodes(data=True):
        clean_attrs = {k: _to_str(v) for k, v in attrs.items()}
        export_graph.add_node(str(node_id), **clean_attrs)

    for u, v, attrs in graph.edges(data=True):
        clean_attrs = {k: _to_str(v) for k, v in attrs.items()}
        export_graph.add_edge(str(u), str(v), **clean_attrs)

    return export_graph


def _to_str(value) -> str:
    """Convert any value to a string for GEXF export."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)
