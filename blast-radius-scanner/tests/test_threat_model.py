"""Tests for the threat-model-aware reachability model.

These use synthetic DiscoveryResult fixtures so they run without AWS credentials.
"""

from __future__ import annotations

from blast_radius_scanner.entry_point_selector import select_entry_point
from blast_radius_scanner.graph import build_attack_graph
from blast_radius_scanner.models import (
    DiscoveryResult,
    DynamoDBTable,
    EC2Instance,
    LambdaFunction,
    S3Bucket,
)
from blast_radius_scanner.reachability.iam import _arn_to_target_id, _get_wildcard_targets
from blast_radius_scanner.reachability.identity import discover_identity_edges
from blast_radius_scanner.reachability.metadata import discover_metadata_edges
from blast_radius_scanner.reachability.network import Edge
from blast_radius_scanner.scorer import score_blast_radius, score_control_effectiveness


def _discovery(imds: str = "optional") -> DiscoveryResult:
    """Two compute resources sharing an account with three data resources."""
    return DiscoveryResult(
        ec2_instances=[
            EC2Instance(
                instance_id="i-aaa",
                name="web",
                state="running",
                vpc_id="vpc-1",
                subnet_id="subnet-1",
                private_ip="10.0.0.5",
                public_ip="1.2.3.4",
                iam_role_name="web-role",
                imds_http_tokens=imds,
                imds_hop_limit=1,
            )
        ],
        lambda_functions=[
            LambdaFunction(
                function_name="broad-fn",
                function_arn="arn:aws:lambda:eu-central-1:1:function:broad-fn",
                runtime="python3.11",
                role_arn="arn:aws:iam::1:role/broad-role",
                role_name="broad-role",
            ),
            LambdaFunction(
                function_name="narrow-fn",
                function_arn="arn:aws:lambda:eu-central-1:1:function:narrow-fn",
                runtime="python3.11",
                role_arn="arn:aws:iam::1:role/narrow-role",
                role_name="narrow-role",
            ),
        ],
        s3_buckets=[S3Bucket(name="bucket-a"), S3Bucket(name="bucket-b")],
        dynamodb_tables=[
            DynamoDBTable(table_name="table-a", table_arn="arn:aws:dynamodb:::table/table-a", status="ACTIVE")
        ],
        iam_roles=["web-role", "broad-role", "narrow-role", "admin-role"],
    )


def _iam_edges() -> list[Edge]:
    """broad-role reaches everything; narrow-role reaches one table; web-role one bucket."""
    edges = [
        Edge("iam_role:broad-role", "s3:bucket-a", "iam", label="s3:GetObject"),
        Edge("iam_role:broad-role", "s3:bucket-b", "iam", label="s3:GetObject"),
        Edge("iam_role:broad-role", "dynamodb:table-a", "iam", label="dynamodb:Scan"),
        Edge("iam_role:narrow-role", "dynamodb:table-a", "iam", label="dynamodb:GetItem"),
        Edge("iam_role:web-role", "s3:bucket-a", "iam", label="s3:GetObject"),
    ]
    return edges


# --- Change 1: identity edges ---------------------------------------------------------


def test_lambda_gets_identity_edge_to_its_role():
    """Regression: Lambda previously had no outgoing edge, forcing BR to 0%."""
    edges = discover_identity_edges(_discovery())
    lambda_edges = [
        e for e in edges if e.source_id.startswith("arn:aws:lambda")
    ]
    assert len(lambda_edges) == 2
    targets = {e.target_id for e in lambda_edges}
    assert targets == {"iam_role:broad-role", "iam_role:narrow-role"}
    assert all(e.edge_type == "identity" for e in lambda_edges)


def test_identity_edge_for_ec2_is_independent_of_imds_version():
    """Code execution on the box yields the role regardless of IMDSv2."""
    v1 = discover_identity_edges(_discovery(imds="optional"))
    v2 = discover_identity_edges(_discovery(imds="required"))
    ec2_v1 = [e for e in v1 if e.source_id == "i-aaa"]
    ec2_v2 = [e for e in v2 if e.source_id == "i-aaa"]
    assert len(ec2_v1) == 1
    assert len(ec2_v2) == 1


def test_metadata_edge_still_gated_on_imds_version():
    """TM2 must keep the IMDS gate, otherwise IMDSv2 becomes unmeasurable."""
    assert len(discover_metadata_edges(_discovery(imds="optional"))) == 1
    assert len(discover_metadata_edges(_discovery(imds="required"))) == 0


def test_lambda_blast_radius_is_nonzero_under_code_exec():
    """The headline regression: broad-fn must now reach the resources its role can."""
    discovery = _discovery()
    edges = discover_identity_edges(discovery) + _iam_edges()
    graph = build_attack_graph(discovery, edges)
    scoring = score_blast_radius(graph, "arn:aws:lambda:eu-central-1:1:function:broad-fn")
    assert scoring.blast_radius_percent > 0
    assert "s3:bucket-a" in scoring.reachable_resource_ids
    assert "dynamodb:table-a" in scoring.reachable_resource_ids


# --- Change 2: role chaining ----------------------------------------------------------


def test_assume_role_wildcard_resolves_to_role_targets():
    """Previously returned [] because there was no assume_role branch."""
    targets = _get_wildcard_targets("assume_role", _discovery())
    assert "iam_role:admin-role" in targets
    assert len(targets) == 4


def test_full_access_includes_role_chaining():
    """Action "*" subsumes sts:AssumeRole, so roles must be reachable targets."""
    targets = _get_wildcard_targets("full_access", _discovery())
    assert any(t.startswith("iam_role:") for t in targets)


def test_role_arn_resolves_to_role_node():
    """Previously returned None because there was no :role/ handler."""
    resolved = _arn_to_target_id("arn:aws:iam::1:role/admin-role", "assume_role", _discovery())
    assert resolved == "iam_role:admin-role"


def test_role_chain_extends_reachability_transitively():
    """web-role -> admin-role -> bucket-b must be reachable from the instance."""
    discovery = _discovery()
    edges = discover_identity_edges(discovery) + [
        Edge("iam_role:web-role", "iam_role:admin-role", "iam", label="sts:AssumeRole"),
        Edge("iam_role:admin-role", "s3:bucket-b", "iam", label="s3:GetObject"),
    ]
    graph = build_attack_graph(discovery, edges)
    scoring = score_blast_radius(graph, "i-aaa")
    assert "s3:bucket-b" in scoring.reachable_resource_ids


# --- Change 3: control effectiveness -------------------------------------------------


def test_imdsv2_has_no_effect_under_code_exec():
    """CE(IMDSv2) must be 0 in TM1 — this is the corrected finding."""
    discovery = _discovery()
    edges = discover_identity_edges(discovery) + _iam_edges()
    before = build_attack_graph(discovery, edges)
    after = build_attack_graph(discovery, [e for e in edges if e.edge_type != "metadata"])
    assert score_control_effectiveness(before, after, "i-aaa") == 0.0


def test_imdsv2_reduces_blast_radius_under_ssrf():
    """CE(IMDSv2) must be positive in TM2, where the control actually applies."""
    discovery = _discovery()
    edges = discover_metadata_edges(discovery) + _iam_edges()
    before = build_attack_graph(discovery, edges)
    after = build_attack_graph(discovery, [e for e in edges if e.edge_type != "metadata"])
    ce = score_control_effectiveness(before, after, "i-aaa")
    assert ce > 0


# --- Change 4: entry point differentiation -------------------------------------------


def test_lambda_scores_differentiate_by_role_breadth():
    """Previously every Lambda tied at 20/100, making auto-selection arbitrary."""
    discovery = _discovery()
    candidates = select_entry_point(discovery, edges=_iam_edges())
    by_name = {c.name: c.score for c in candidates}
    assert by_name["broad-fn"] > by_name["narrow-fn"]


def test_selector_without_edges_still_works():
    """Fallback path must not raise when no edge list is supplied."""
    candidates = select_entry_point(_discovery())
    assert len(candidates) == 3


# --- Change 5: stopped instances -----------------------------------------------------


def test_stopped_instances_excluded_by_default_and_includable():
    discovery = _discovery()
    discovery.ec2_instances[0].state = "stopped"
    assert not any(c.resource_type == "ec2" for c in select_entry_point(discovery))
    included = select_entry_point(discovery, include_stopped=True)
    assert any(c.resource_type == "ec2" for c in included)
