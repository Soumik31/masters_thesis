"""Tests for credential-store and log read access.

Reading a secret or SSM parameter usually yields credentials to a system the compromised
resource cannot otherwise reach, so these read-only actions extend blast radius. They were
previously unmodelled, which understated results: an RDS instance could appear reachable
while the credential needed to use it did not appear at all.
"""

from __future__ import annotations

from blast_radius_scanner.graph import build_attack_graph
from blast_radius_scanner.models import DiscoveryResult, LambdaFunction, RDSInstance
from blast_radius_scanner.reachability.iam import (
    LOGS_NODE,
    _arn_to_target_id,
    _get_wildcard_targets,
    _match_actions,
    _match_statements_to_resources,
)
from blast_radius_scanner.reachability.identity import discover_identity_edges
from blast_radius_scanner.scorer import score_blast_radius

ACCOUNT = "111122223333"


def _discovery() -> DiscoveryResult:
    return DiscoveryResult(
        lambda_functions=[
            LambdaFunction(
                function_name="app",
                function_arn=f"arn:aws:lambda:eu-central-1:{ACCOUNT}:function:app",
                runtime="python3.11",
                role_arn=f"arn:aws:iam::{ACCOUNT}:role/app-role",
                role_name="app-role",
            )
        ],
        rds_instances=[
            RDSInstance(db_instance_id="wordpress-db", engine="mysql", vpc_id="vpc-1")
        ],
        secrets=["wordpress/db-credentials", "third-party/api-key"],
        ssm_parameters=["/app/db-password", "/app/feature-flag"],
    )


# --- actions are recognised -----------------------------------------------------------


def test_secret_read_actions_are_modelled():
    for action in (
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:*",
    ):
        assert _match_actions([action]), f"{action} should be modelled"


def test_parameter_read_actions_are_modelled():
    for action in ("ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"):
        assert _match_actions([action]), f"{action} should be modelled"


def test_log_read_is_modelled_but_log_write_is_not():
    """Reading log content is data access; writing a log line is not."""
    assert _match_actions(["logs:FilterLogEvents"]) == [
        ("logs:FilterLogEvents", "logs_read")
    ]
    assert _match_actions(["logs:GetLogEvents"]) == [("logs:GetLogEvents", "logs_read")]
    assert _match_actions(["logs:PutLogEvents"]) == []
    assert _match_actions(["logs:CreateLogStream"]) == []


def test_kms_decrypt_is_modelled():
    assert _match_actions(["kms:Decrypt"]) == [("kms:Decrypt", "kms_decrypt")]


# --- targets resolve ------------------------------------------------------------------


def test_wildcard_secret_grant_reaches_every_secret():
    targets = _get_wildcard_targets("secret_read", _discovery())
    assert set(targets) == {
        "secret:wordpress/db-credentials",
        "secret:third-party/api-key",
    }


def test_wildcard_parameter_grant_reaches_every_parameter():
    targets = _get_wildcard_targets("parameter_read", _discovery())
    assert set(targets) == {"ssm:/app/db-password", "ssm:/app/feature-flag"}


def test_log_read_resolves_to_the_aggregate_node():
    assert _get_wildcard_targets("logs_read", _discovery()) == [LOGS_NODE]


def test_secret_arn_with_aws_suffix_resolves():
    """AWS appends a random suffix to secret ARNs, so matching must tolerate it."""
    arn = f"arn:aws:secretsmanager:eu-central-1:{ACCOUNT}:secret:wordpress/db-credentials-AbCdEf"
    assert _arn_to_target_id(arn, "secret_read", _discovery()) == "secret:wordpress/db-credentials"


def test_parameter_arn_resolves():
    arn = f"arn:aws:ssm:eu-central-1:{ACCOUNT}:parameter/app/db-password"
    assert _arn_to_target_id(arn, "parameter_read", _discovery()) == "ssm:/app/db-password"


def test_unknown_secret_arn_does_not_resolve():
    arn = f"arn:aws:secretsmanager:eu-central-1:{ACCOUNT}:secret:not-discovered-XyZ"
    assert _arn_to_target_id(arn, "secret_read", _discovery()) is None


def test_full_access_includes_credential_stores():
    targets = _get_wildcard_targets("full_access", _discovery())
    assert "secret:wordpress/db-credentials" in targets
    assert "ssm:/app/db-password" in targets
    assert LOGS_NODE in targets


# --- end to end -----------------------------------------------------------------------


def test_scoped_secret_grant_produces_one_edge_only():
    """Least privilege must be visible: one secret granted, one edge produced."""
    stmt = [
        {
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": f"arn:aws:secretsmanager:eu-central-1:{ACCOUNT}:secret:wordpress/db-credentials-AbCdEf",
        }
    ]
    edges = _match_statements_to_resources("app-role", stmt, _discovery())
    assert [e.target_id for e in edges] == ["secret:wordpress/db-credentials"]


def test_credential_store_is_counted_in_blast_radius():
    """The regression: a reachable database credential must appear in the score."""
    discovery = _discovery()
    stmt = [
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
    ]
    edges = discover_identity_edges(discovery) + _match_statements_to_resources(
        "app-role", stmt, discovery
    )
    graph = build_attack_graph(discovery, edges)
    scoring = score_blast_radius(
        graph, f"arn:aws:lambda:eu-central-1:{ACCOUNT}:function:app"
    )
    assert "secret:wordpress/db-credentials" in scoring.reachable_resource_ids
    assert scoring.blast_radius_percent > 0


def test_secrets_and_parameters_become_graph_nodes():
    graph = build_attack_graph(_discovery(), [])
    types = {
        graph.nodes[n].get("resource_type")
        for n in graph.nodes
    }
    assert "secret" in types
    assert "ssm_parameter" in types


def test_total_resources_counts_credential_stores():
    d = _discovery()
    # 1 lambda + 1 rds + 2 secrets + 2 parameters
    assert d.total_resources == 6
