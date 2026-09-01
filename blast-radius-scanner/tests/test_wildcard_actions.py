"""Tests for prefixed wildcard actions.

A policy action such as ``ssm:List*`` previously matched the pattern ``ssm:*`` — because
``ssm:List*`` does start with ``ssm:`` — and was scored as full parameter access. The three
actions below dominated the 01092026 serverless scans and produced 570 of the edges that
held those accounts at 96-98%:

    kms:GenerateDataKey*   208 edges   creates a key for encryption, decrypts nothing
    ssm:List*              200 edges   lists documents, does not read parameter values
    lambda:List*           162 edges   lists functions, does not invoke them
"""

from __future__ import annotations

from blast_radius_scanner.models import (
    DiscoveryResult,
    DynamoDBTable,
    LambdaFunction,
    S3Bucket,
)
from blast_radius_scanner.reachability.iam import _match_actions, _match_statements_to_resources

ACCOUNT = "905418363445"


def _discovery() -> DiscoveryResult:
    return DiscoveryResult(
        lambda_functions=[
            LambdaFunction(
                function_name=f"fn{i}",
                function_arn=f"arn:aws:lambda:eu-central-1:{ACCOUNT}:function:fn{i}",
                runtime="python3.11",
                role_arn=f"arn:aws:iam::{ACCOUNT}:role/r",
                role_name="r",
            )
            for i in range(3)
        ],
        s3_buckets=[S3Bucket(name="b1"), S3Bucket(name="b2")],
        dynamodb_tables=[
            DynamoDBTable(table_name="t1", table_arn="arn:aws:dynamodb:::table/t1", status="ACTIVE")
        ],
        secrets=["s1", "s2"],
        ssm_parameters=["/p1", "/p2", "/p3"],
    )


# --- the three offenders --------------------------------------------------------------


def test_ssm_list_does_not_grant_parameter_access():
    assert _match_actions(["ssm:List*"]) == []
    assert _match_actions(["ssm:ListDocuments"]) == []
    assert _match_actions(["ssm:ListTagsForResource"]) == []


def test_lambda_list_does_not_grant_invoke():
    assert _match_actions(["lambda:List*"]) == []
    assert _match_actions(["lambda:ListFunctions"]) == []


def test_generate_data_key_does_not_grant_decrypt():
    assert _match_actions(["kms:GenerateDataKey*"]) == []
    assert _match_actions(["kms:GenerateDataKey"]) == []
    assert _match_actions(["kms:Encrypt"]) == []


def test_offending_actions_produce_no_edges_end_to_end():
    stmt = [
        {
            "Effect": "Allow",
            "Action": ["kms:GenerateDataKey*", "ssm:List*", "lambda:List*"],
            "Resource": "*",
        }
    ]
    assert _match_statements_to_resources("r", stmt, _discovery()) == []


# --- legitimate prefixed wildcards must still work ------------------------------------


def test_get_prefix_still_grants_parameter_read():
    """ssm:Get* covers ssm:GetParameter, so it must still match."""
    matched = _match_actions(["ssm:Get*"])
    assert matched and matched[0][1].startswith("parameter")


def test_service_wildcard_still_grants_full_access():
    assert _match_actions(["ssm:*"]) == [("ssm:*", "parameter_full")]
    assert _match_actions(["s3:*"]) == [("s3:*", "s3_full")]
    assert _match_actions(["lambda:*"]) == [("lambda:*", "lambda_full")]
    assert _match_actions(["kms:*"]) == [("kms:*", "kms_decrypt")]


def test_put_object_prefix_still_grants_write():
    matched = _match_actions(["s3:PutObject*"])
    assert matched and matched[0][1] == "s3_write"


def test_s3_list_prefix_still_grants_read():
    """s3:List* covers s3:ListBucket, which is enumeration of bucket contents."""
    matched = _match_actions(["s3:List*"])
    assert matched and matched[0][1] == "s3_read"


def test_specific_actions_unaffected():
    assert _match_actions(["ssm:GetParameter"])[0][1] == "parameter_read"
    assert _match_actions(["kms:Decrypt"])[0][1] == "kms_decrypt"
    assert _match_actions(["lambda:InvokeFunction"])[0][1] == "lambda_invoke"
    assert _match_actions(["secretsmanager:GetSecretValue"])[0][1] == "secret_read"


def test_literal_admin_still_full_access():
    assert _match_actions(["*"]) == [("*", "full_access")]


# --- newly modelled DynamoDB actions --------------------------------------------------


def test_dynamodb_batch_and_update_actions_are_modelled():
    """These appeared 35 times in the real scans and were silently ignored."""
    assert _match_actions(["dynamodb:BatchWriteItem"])[0][1] == "dynamodb_write"
    assert _match_actions(["dynamodb:BatchGetItem"])[0][1] == "dynamodb_read"
    assert _match_actions(["dynamodb:UpdateItem"])[0][1] == "dynamodb_write"


# --- kms:Decrypt reaches nothing on its own -------------------------------------------


def test_kms_decrypt_produces_no_edges():
    """154 spurious edges in article-generation-prod came from treating decryption as
    access to every secret and parameter. Decrypting requires already holding the
    ciphertext, which needs a separate retrieval permission."""
    stmt = [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]
    assert _match_statements_to_resources("r", stmt, _discovery()) == []


def test_kms_action_is_still_recognised():
    """Recognised so it is recorded rather than silently unmatched, but yields no target."""
    assert _match_actions(["kms:Decrypt"]) == [("kms:Decrypt", "kms_decrypt")]


# --- only value-revealing secret actions count ----------------------------------------


def test_secret_metadata_actions_do_not_grant_value_access():
    """DescribeSecret and ListSecretVersionIds return metadata, not secret material."""
    for action in (
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecretVersionIds",
        "secretsmanager:ListSecrets",
        "secretsmanager:List*",
    ):
        assert _match_actions([action]) == [], f"{action} should not match"


def test_get_secret_value_still_grants_access():
    d = _discovery()
    stmt = [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]
    edges = _match_statements_to_resources("r", stmt, d)
    assert len(edges) == len(d.secrets)


def test_secretsmanager_service_wildcard_still_grants_access():
    d = _discovery()
    stmt = [{"Effect": "Allow", "Action": "secretsmanager:*", "Resource": "*"}]
    edges = _match_statements_to_resources("r", stmt, d)
    assert len(edges) == len(d.secrets)


def test_ssm_get_prefix_still_reaches_parameters():
    """ssm:Get* was 144 real edges in the scan and must be preserved."""
    d = _discovery()
    stmt = [{"Effect": "Allow", "Action": "ssm:Get*", "Resource": "*"}]
    edges = _match_statements_to_resources("r", stmt, d)
    assert len(edges) == len(d.ssm_parameters)
