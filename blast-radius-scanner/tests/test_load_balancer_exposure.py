"""Tests for internet-facing load balancer exposure.

Regression: the WordPress instance in account 851725489819 sits in a private subnet behind
an ALB and has no public IP, so an exposure check based on public_ip alone reported the
account as having no externally reachable entry point at all.
"""

from __future__ import annotations

from blast_radius_scanner.discovery.exposure import (
    EXPOSURE_INTERNET_FACING_LB,
    UNAUTHENTICATED_EXPOSURES,
    discover_load_balancer_exposures,
)
from blast_radius_scanner.entry_point_selector import select_entry_point
from blast_radius_scanner.models import DiscoveryResult, EC2Instance


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class _FakeElbv2:
    """Stub modelling one internet-facing and one internal balancer."""

    def __init__(self, schemes: dict[str, str], targets: dict[str, list[str]]):
        self._schemes = schemes
        self._targets = targets

    def get_paginator(self, name):
        if name == "describe_load_balancers":
            return _FakePaginator([
                {"LoadBalancers": [
                    {"LoadBalancerArn": arn, "Scheme": scheme}
                    for arn, scheme in self._schemes.items()
                ]}
            ])
        if name == "describe_target_groups":
            return self

        raise AssertionError(f"unexpected paginator {name}")

    # describe_target_groups paginator behaviour, parameterised by LoadBalancerArn
    def paginate(self, LoadBalancerArn=None):  # noqa: N803 - boto3 casing
        return [{"TargetGroups": [{"TargetGroupArn": f"tg-for-{LoadBalancerArn}"}]}]

    def describe_target_health(self, TargetGroupArn):  # noqa: N803
        lb_arn = TargetGroupArn.removeprefix("tg-for-")
        return {
            "TargetHealthDescriptions": [
                {"Target": {"Id": tid}} for tid in self._targets.get(lb_arn, [])
            ]
        }


class _FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, name):
        if name != "elbv2":
            raise AssertionError(f"unexpected client {name}")
        return self._client


def test_internet_facing_lb_targets_are_exposed():
    elbv2 = _FakeElbv2(
        schemes={"lb-public": "internet-facing"},
        targets={"lb-public": ["i-web1", "i-web2"]},
    )
    result = discover_load_balancer_exposures(_FakeSession(elbv2))
    assert result == {
        "i-web1": [EXPOSURE_INTERNET_FACING_LB],
        "i-web2": [EXPOSURE_INTERNET_FACING_LB],
    }


def test_internal_lb_targets_are_not_exposed():
    elbv2 = _FakeElbv2(
        schemes={"lb-internal": "internal"},
        targets={"lb-internal": ["i-worker"]},
    )
    assert discover_load_balancer_exposures(_FakeSession(elbv2)) == {}


def test_only_public_balancer_targets_are_selected():
    elbv2 = _FakeElbv2(
        schemes={"lb-public": "internet-facing", "lb-internal": "internal"},
        targets={"lb-public": ["i-web"], "lb-internal": ["i-worker"]},
    )
    result = discover_load_balancer_exposures(_FakeSession(elbv2))
    assert "i-web" in result
    assert "i-worker" not in result


def test_missing_permission_degrades_quietly():
    class _Broken:
        def client(self, name):
            raise Exception("AccessDenied")

    assert discover_load_balancer_exposures(_Broken()) == {}


def test_lb_exposure_counts_as_unauthenticated():
    assert EXPOSURE_INTERNET_FACING_LB in UNAUTHENTICATED_EXPOSURES


# --- selector integration ------------------------------------------------------------


def _instance(instance_id: str, public_ip: str | None, exposures: list[str]) -> EC2Instance:
    return EC2Instance(
        instance_id=instance_id,
        name=instance_id,
        state="running",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        private_ip="10.0.0.5",
        public_ip=public_ip,
        iam_role_name="web-role",
        exposures=exposures,
    )


def test_private_instance_behind_public_alb_is_externally_reachable():
    """The exact WordPress topology that previously yielded zero entry points."""
    discovery = DiscoveryResult(
        ec2_instances=[_instance("i-web", None, [EXPOSURE_INTERNET_FACING_LB])]
    )
    candidates = select_entry_point(discovery, exposed_only=True)
    assert [c.resource_id for c in candidates] == ["i-web"]


def test_private_instance_with_no_exposure_is_excluded():
    discovery = DiscoveryResult(ec2_instances=[_instance("i-worker", None, [])])
    assert select_entry_point(discovery, exposed_only=True) == []


def test_public_ip_still_counts():
    discovery = DiscoveryResult(ec2_instances=[_instance("i-direct", "1.2.3.4", [])])
    candidates = select_entry_point(discovery, exposed_only=True)
    assert [c.resource_id for c in candidates] == ["i-direct"]


def test_alb_reason_is_reported():
    discovery = DiscoveryResult(
        ec2_instances=[_instance("i-web", None, [EXPOSURE_INTERNET_FACING_LB])]
    )
    candidate = select_entry_point(discovery)[0]
    assert any("internet-facing load balancer" in r for r in candidate.reasons)
