"""Tests for IAM action matching and target resolution.

The action cases below are the permissions that actually dominated the 21082026 scans:
logs:PutLogEvents alone produced 23,484 of 53,977 edges because unrecognised actions fell
through to the full_access catch-all.
"""

from __future__ import annotations

from blast_radius_scanner.models import (
    DiscoveryResult,
    DynamoDBTable,
    EC2Instance,
    LambdaFunction,
    S3Bucket,
)
from blast_radius_scanner.reachability.iam import (
    _arn_to_target_id,
    _get_wildcard_targets,
    _match_actions,
    _match_statements_to_resources,
)


def _discovery() -> DiscoveryResult:
    return DiscoveryResult(
        ec2_instances=[
            EC2Instance(
                instance_id="i-aaa",
                name="web",
                state="running",
                vpc_id="vpc-1",
                subnet_id="subnet-1",
                private_ip="10.0.0.5",
                public_ip=None,
                iam_role_name="web-role",
            )
        ],
        lambda_functions=[
            LambdaFunction(
                function_name="fn",
                function_arn="arn:aws:lambda:eu-central-1:1:function:fn",
                runtime="python3.11",
                role_arn="arn:aws:iam::1:role/fn-role",
                role_name="fn-role",
            )
        ],
        s3_buckets=[S3Bucket(name="bucket-a"), S3Bucket(name="bucket-b")],
        dynamodb_tables=[
            DynamoDBTable(table_name="table-a", table_arn="arn:aws:dynamodb:::table/table-a", status="ACTIVE")
        ],
        iam_roles=[
            "web-role",
            "fn-role",
            "app-role",
            # None of these are assumable by a workload role
            "AWSServiceRoleForOrganizations",
            "AWSReservedSSO_AWSAdministratorAccess_abc",
            "aws-controltower-AdministratorExecutionRole",
            "stacksets-exec-deadbeef",
        ],
    )


# --- unrecognised actions must not imply full access ---------------------------------


def test_cloudwatch_logs_actions_produce_no_edges():
    """The defect that inflated every account: log permissions are not full access."""
    for action in (
        "logs:PutLogEvents",
        "logs:FilterLogEvents",
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
    ):
        assert _match_actions([action]) == [], f"{action} should not match"


def test_other_harmless_actions_produce_no_edges():
    for action in (
        "cloudwatch:PutMetricData",
        "xray:ListTagsForResource",
        "sqs:ListQueues",
        "ecr:GetAuthorizationToken",
        "s3express:CreateSession",
    ):
        assert _match_actions([action]) == [], f"{action} should not match"


def test_logs_permission_on_wildcard_resource_yields_no_edges():
    """End to end: the statement shape that produced 23,484 edges must produce none."""
    stmt = [{"Effect": "Allow", "Action": ["logs:PutLogEvents"], "Resource": ["*"]}]
    edges = _match_statements_to_resources("web-role", stmt, _discovery())
    assert edges == []


# --- genuine grants must still be detected -------------------------------------------


def test_literal_wildcard_action_is_full_access():
    """Action "*" previously matched s3:GetObject, under-counting real admin."""
    assert _match_actions(["*"]) == [("*", "full_access")]


def test_admin_statement_reaches_many_resource_types():
    stmt = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    edges = _match_statements_to_resources("app-role", stmt, _discovery())
    types = {t.split(":")[0] for t in (e.target_id for e in edges)}
    assert "s3" in types
    assert "dynamodb" in types
    assert "iam_role" in types


def test_specific_and_service_wildcard_actions_still_match():
    assert _match_actions(["s3:GetObject"]) == [("s3:GetObject", "s3_read")]
    assert _match_actions(["s3:*"]) == [("s3:*", "s3_full")]
    assert _match_actions(["dynamodb:Scan"]) == [("dynamodb:Scan", "dynamodb_read")]
    assert _match_actions(["sts:AssumeRole"]) == [("sts:AssumeRole", "assume_role")]


def test_mixed_statement_keeps_only_the_meaningful_action():
    """A role with logs plus S3 should yield S3 edges only."""
    stmt = [
        {
            "Effect": "Allow",
            "Action": ["logs:PutLogEvents", "s3:GetObject"],
            "Resource": ["*"],
        }
    ]
    edges = _match_statements_to_resources("web-role", stmt, _discovery())
    assert edges, "expected S3 edges"
    assert {e.details["action"] for e in edges} == {"s3:GetObject"}


def test_deny_statements_are_ignored():
    stmt = [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    assert _match_statements_to_resources("web-role", stmt, _discovery()) == []


# --- phantom nodes and non-assumable roles -------------------------------------------


def test_wildcard_role_arns_do_not_create_phantom_nodes():
    """These produced iam_role:* and iam_role:*AWSBackup* in the 21082026 scan."""
    for arn in (
        "arn:aws:iam::123:role/*",
        "arn:aws:iam::*:role/*AWSBackup*",
        "arn:aws:iam::*:role/*AmazonSageMaker*",
    ):
        assert _arn_to_target_id(arn, "assume_role", _discovery()) is None


def test_specific_role_arn_still_resolves():
    assert (
        _arn_to_target_id("arn:aws:iam::1:role/app-role", "assume_role", _discovery())
        == "iam_role:app-role"
    )


def test_service_linked_and_sso_roles_excluded_from_assume_targets():
    targets = _get_wildcard_targets("assume_role", _discovery())
    assert "iam_role:app-role" in targets
    for excluded in (
        "iam_role:AWSServiceRoleForOrganizations",
        "iam_role:AWSReservedSSO_AWSAdministratorAccess_abc",
        "iam_role:aws-controltower-AdministratorExecutionRole",
        "iam_role:stacksets-exec-deadbeef",
    ):
        assert excluded not in targets
