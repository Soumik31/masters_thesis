"""Tests for exposure detection and exposed-only entry point selection.

Exposure answers "can an untrusted caller reach this at all", which is the precondition for
blast radius being a meaningful question about that resource.
"""

from __future__ import annotations

from blast_radius_scanner.discovery.exposure import (
    EXPOSURE_API_GATEWAY,
    EXPOSURE_EVENT_SOURCE,
    EXPOSURE_PUBLIC_FUNCTION_URL,
    EXPOSURE_WILDCARD_PRINCIPAL,
    _iter_principals,
    _resource_policy_exposure,
)
from blast_radius_scanner.entry_point_selector import select_entry_point
from blast_radius_scanner.models import DiscoveryResult, EC2Instance, LambdaFunction, S3Bucket


class _FakeLambdaClient:
    """Minimal stub returning a canned resource policy."""

    def __init__(self, policy: str | None):
        self._policy = policy

    def get_policy(self, FunctionName: str):  # noqa: N803 - boto3 casing
        if self._policy is None:
            raise Exception("ResourceNotFoundException")
        return {"Policy": self._policy}


def _fn(name: str, role: str, exposures: list[str]) -> LambdaFunction:
    return LambdaFunction(
        function_name=name,
        function_arn=f"arn:aws:lambda:eu-central-1:1:function:{name}",
        runtime="python3.11",
        role_arn=f"arn:aws:iam::1:role/{role}",
        role_name=role,
        exposures=exposures,
    )


def _ec2(instance_id: str, public_ip: str | None) -> EC2Instance:
    return EC2Instance(
        instance_id=instance_id,
        name=instance_id,
        state="running",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        private_ip="10.0.0.5",
        public_ip=public_ip,
        iam_role_name="web-role",
    )


# --- resource policy parsing ---------------------------------------------------------


def test_wildcard_principal_is_detected():
    policy = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}]}'
    assert _resource_policy_exposure(_FakeLambdaClient(policy), "arn") == [
        EXPOSURE_WILDCARD_PRINCIPAL
    ]


def test_api_gateway_principal_is_detected():
    policy = (
        '{"Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"apigateway.amazonaws.com"},'
        '"Action":"lambda:InvokeFunction"}]}'
    )
    assert _resource_policy_exposure(_FakeLambdaClient(policy), "arn") == [
        EXPOSURE_API_GATEWAY
    ]


def test_named_account_principal_is_not_exposure():
    """A specific account principal still requires credentials."""
    policy = (
        '{"Statement":[{"Effect":"Allow",'
        '"Principal":{"AWS":"arn:aws:iam::111122223333:root"},'
        '"Action":"lambda:InvokeFunction"}]}'
    )
    assert _resource_policy_exposure(_FakeLambdaClient(policy), "arn") == []


def test_deny_statement_is_not_exposure():
    policy = '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction"}]}'
    assert _resource_policy_exposure(_FakeLambdaClient(policy), "arn") == []


def test_missing_policy_is_not_exposure():
    assert _resource_policy_exposure(_FakeLambdaClient(None), "arn") == []


def test_malformed_policy_is_not_exposure():
    assert _resource_policy_exposure(_FakeLambdaClient("not json"), "arn") == []


def test_principal_shapes_are_normalised():
    assert _iter_principals("*") == ["*"]
    assert _iter_principals({"Service": "apigateway.amazonaws.com"}) == [
        "apigateway.amazonaws.com"
    ]
    assert _iter_principals({"AWS": ["a", "b"]}) == ["a", "b"]
    assert _iter_principals(None) == []


# --- exposed-only selection ----------------------------------------------------------


def _mixed_discovery() -> DiscoveryResult:
    return DiscoveryResult(
        ec2_instances=[_ec2("i-public", "1.2.3.4"), _ec2("i-private", None)],
        lambda_functions=[
            _fn("public-url-fn", "r1", [EXPOSURE_PUBLIC_FUNCTION_URL]),
            _fn("open-policy-fn", "r2", [EXPOSURE_WILDCARD_PRINCIPAL]),
            _fn("apigw-fn", "r3", [EXPOSURE_API_GATEWAY]),
            _fn("event-fn", "r4", [EXPOSURE_EVENT_SOURCE]),
            _fn("internal-fn", "r5", []),
        ],
        s3_buckets=[S3Bucket(name="b")],
    )


def test_exposed_only_keeps_unauthenticated_reachable_resources():
    names = {c.name for c in select_entry_point(_mixed_discovery(), exposed_only=True)}
    assert names == {"i-public", "public-url-fn", "open-policy-fn"}


def test_exposed_only_excludes_internal_and_ambiguous_resources():
    """API Gateway and event sources may still require access, so they are not counted."""
    names = {c.name for c in select_entry_point(_mixed_discovery(), exposed_only=True)}
    assert "internal-fn" not in names
    assert "apigw-fn" not in names
    assert "event-fn" not in names
    assert "i-private" not in names


def test_without_filter_all_candidates_returned_but_flagged():
    candidates = select_entry_point(_mixed_discovery())
    assert len(candidates) == 7
    external = {c.name for c in candidates if c.is_externally_reachable}
    assert external == {"i-public", "public-url-fn", "open-policy-fn"}


def test_public_function_url_outranks_internal_function():
    candidates = {c.name: c.score for c in select_entry_point(_mixed_discovery())}
    assert candidates["public-url-fn"] > candidates["internal-fn"]


def test_internal_function_reason_explains_why():
    candidates = {c.name: c for c in select_entry_point(_mixed_discovery())}
    assert any(
        "internal only" in r for r in candidates["internal-fn"].reasons
    )
