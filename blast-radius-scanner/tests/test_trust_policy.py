"""Tests for trust policy evaluation on role chaining.

Regression: in account 905418363445 an API authorizer role held sts:AssumeRole on "*",
which produced a chain to cdk-hnb659fds-cfn-exec-role (Action "*") and a 97.8% blast
radius. That CDK role trusts only cloudformation.amazonaws.com, so the chain was false.
"""

from __future__ import annotations

import json

from blast_radius_scanner.models import DiscoveryResult, LambdaFunction
from blast_radius_scanner.reachability.iam import (
    _account_id_from_discovery,
    _get_trust_policy_principals,
    _trust_permits_role,
)

ACCOUNT = "905418363445"


class _FakeIam:
    def __init__(self, policies: dict[str, dict]):
        self._policies = policies

    def get_role(self, RoleName: str):  # noqa: N803 - boto3 casing
        if RoleName not in self._policies:
            raise Exception("NoSuchEntity")
        return {"Role": {"AssumeRolePolicyDocument": self._policies[RoleName]}}


def _trust(principal, action="sts:AssumeRole", effect="Allow"):
    return {"Statement": [{"Effect": effect, "Action": action, "Principal": principal}]}


def _discovery() -> DiscoveryResult:
    return DiscoveryResult(
        lambda_functions=[
            LambdaFunction(
                function_name="authorizer",
                function_arn=f"arn:aws:lambda:eu-central-1:{ACCOUNT}:function:authorizer",
                runtime="python3.11",
                role_arn=f"arn:aws:iam::{ACCOUNT}:role/authorizer-role",
                role_name="authorizer-role",
            )
        ]
    )


# --- parsing --------------------------------------------------------------------------


def test_account_id_is_derived_from_discovery():
    assert _account_id_from_discovery(_discovery()) == ACCOUNT


def test_service_principal_is_parsed():
    iam = _FakeIam({"cdk-exec": _trust({"Service": "cloudformation.amazonaws.com"})})
    assert _get_trust_policy_principals(iam, "cdk-exec") == {
        "cloudformation.amazonaws.com"
    }


def test_trust_policy_as_json_string_is_parsed():
    iam = _FakeIam({"r": json.dumps(_trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}))})
    assert _get_trust_policy_principals(iam, "r") == {f"arn:aws:iam::{ACCOUNT}:root"}


def test_unreadable_trust_policy_returns_none():
    assert _get_trust_policy_principals(_FakeIam({}), "missing") is None


def test_non_assumerole_statements_are_ignored():
    iam = _FakeIam({"r": _trust({"AWS": "*"}, action="sts:TagSession")})
    assert _get_trust_policy_principals(iam, "r") == set()


def test_deny_statements_are_ignored():
    iam = _FakeIam({"r": _trust({"AWS": "*"}, effect="Deny")})
    assert _get_trust_policy_principals(iam, "r") == set()


# --- the decision ---------------------------------------------------------------------


def test_cdk_deployment_role_is_not_assumable_by_a_lambda_role():
    """The exact false chain that produced 97.8%."""
    principals = {"cloudformation.amazonaws.com"}
    assert _trust_permits_role(principals, "authorizer-role", ACCOUNT) is False


def test_service_linked_role_is_not_assumable():
    assert _trust_permits_role({"config.amazonaws.com"}, "authorizer-role", ACCOUNT) is False


def test_account_root_principal_permits_any_role_in_the_account():
    principals = {f"arn:aws:iam::{ACCOUNT}:root"}
    assert _trust_permits_role(principals, "authorizer-role", ACCOUNT) is True


def test_exact_role_arn_principal_permits_that_role():
    principals = {f"arn:aws:iam::{ACCOUNT}:role/authorizer-role"}
    assert _trust_permits_role(principals, "authorizer-role", ACCOUNT) is True


def test_exact_role_arn_principal_does_not_permit_a_different_role():
    principals = {f"arn:aws:iam::{ACCOUNT}:role/some-other-role"}
    assert _trust_permits_role(principals, "authorizer-role", ACCOUNT) is False


def test_wildcard_principal_permits_anything():
    assert _trust_permits_role({"*"}, "authorizer-role", ACCOUNT) is True


def test_unknown_trust_policy_is_permitted_to_avoid_deleting_real_paths():
    """A missing iam:GetRole must not silently remove every chain edge."""
    assert _trust_permits_role(None, "authorizer-role", ACCOUNT) is True


def test_empty_trust_policy_permits_nothing():
    assert _trust_permits_role(set(), "authorizer-role", ACCOUNT) is False


def test_role_arn_with_a_path_still_matches():
    principals = {f"arn:aws:iam::{ACCOUNT}:role/service-role/authorizer-role"}
    assert _trust_permits_role(principals, "authorizer-role", ACCOUNT) is True
