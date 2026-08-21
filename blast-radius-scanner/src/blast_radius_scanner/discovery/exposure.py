"""Discover how compute resources are exposed to untrusted callers.

Blast radius answers "how far can an attacker spread from here". That is only a meaningful
question for resources an attacker can actually reach. Without this, every Lambda in an
account is treated as an equally plausible starting point, including functions invoked only
by an internal Step Function, which an unauthenticated attacker cannot reach at all.

Reaching a function and executing code inside it are separate steps. These signals capture
the first step only: whether an untrusted caller can cause the function to run. Executing
arbitrary code additionally requires a flaw in the handler or a compromised dependency,
which is outside what configuration analysis can determine.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3

logger = logging.getLogger(__name__)

# Exposure kinds, ordered roughly by how directly an untrusted caller can reach the function
EXPOSURE_PUBLIC_FUNCTION_URL = "public_function_url"
EXPOSURE_WILDCARD_PRINCIPAL = "wildcard_invoke_principal"
EXPOSURE_API_GATEWAY = "api_gateway"
EXPOSURE_LOAD_BALANCER = "load_balancer"
EXPOSURE_INTERNET_FACING_LB = "internet_facing_load_balancer"
EXPOSURE_EVENT_SOURCE = "event_source"

# Service principals in a resource-based policy that imply a front door
_FRONT_DOOR_SERVICES = {
    "apigateway.amazonaws.com": EXPOSURE_API_GATEWAY,
    "elasticloadbalancing.amazonaws.com": EXPOSURE_LOAD_BALANCER,
}

# Exposures that mean an unauthenticated caller from the internet can reach the resource.
#
# EXPOSURE_LOAD_BALANCER (inferred from a Lambda resource policy) is excluded because the
# policy alone does not say whether the balancer is internet-facing. EXPOSURE_API_GATEWAY is
# excluded because the API may require authentication.
#
# EXPOSURE_INTERNET_FACING_LB is included: it is only set after confirming the balancer's
# Scheme is "internet-facing" and the resource is a registered target. A private instance
# behind a public load balancer is the standard production web pattern, and omitting it
# would miss the most common genuine entry point. Listener-level authentication (OIDC or
# Cognito) is not inspected, so this may over-claim for balancers that authenticate.
UNAUTHENTICATED_EXPOSURES = frozenset(
    {
        EXPOSURE_PUBLIC_FUNCTION_URL,
        EXPOSURE_WILDCARD_PRINCIPAL,
        EXPOSURE_INTERNET_FACING_LB,
    }
)


def discover_load_balancer_exposures(session: boto3.Session) -> dict[str, list[str]]:
    """Return resource ID -> exposure kinds for targets behind internet-facing balancers.

    Keys are EC2 instance IDs or Lambda function ARNs, matching the node identifiers used
    elsewhere. Returns an empty mapping if elasticloadbalancing cannot be queried, so a
    restricted principal degrades rather than failing the scan.

    Only ALB and NLB (elbv2) are covered. Classic ELB is not queried.
    """
    exposures: dict[str, list[str]] = {}
    try:
        client = session.client("elbv2")
        public_lb_arns: list[str] = []
        lb_paginator = client.get_paginator("describe_load_balancers")
        for page in lb_paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("Scheme") == "internet-facing" and lb.get("LoadBalancerArn"):
                    public_lb_arns.append(lb["LoadBalancerArn"])

        if not public_lb_arns:
            logger.info("No internet-facing load balancers found")
            return {}

        for lb_arn in public_lb_arns:
            for target_id in _targets_behind(client, lb_arn):
                exposures.setdefault(target_id, [])
                if EXPOSURE_INTERNET_FACING_LB not in exposures[target_id]:
                    exposures[target_id].append(EXPOSURE_INTERNET_FACING_LB)

        logger.info(
            "Load balancer exposure: %d internet-facing balancer(s), %d target(s) reachable",
            len(public_lb_arns),
            len(exposures),
        )
    except Exception as e:
        logger.warning(
            "Could not query load balancers (instances behind a public ALB will not be "
            "marked externally reachable): %s",
            e,
        )
        return {}

    return exposures


def _targets_behind(client: Any, lb_arn: str) -> list[str]:
    """Registered target IDs for every target group attached to a load balancer."""
    target_ids: list[str] = []
    try:
        tg_paginator = client.get_paginator("describe_target_groups")
        for page in tg_paginator.paginate(LoadBalancerArn=lb_arn):
            for tg in page.get("TargetGroups", []):
                tg_arn = tg.get("TargetGroupArn")
                if not tg_arn:
                    continue
                try:
                    health = client.describe_target_health(TargetGroupArn=tg_arn)
                except Exception:
                    continue
                for entry in health.get("TargetHealthDescriptions", []):
                    tid = entry.get("Target", {}).get("Id")
                    if tid:
                        target_ids.append(tid)
    except Exception as e:
        logger.debug("Could not resolve targets for %s: %s", lb_arn, e)
    return target_ids


def discover_lambda_exposures(session: boto3.Session, function_arns: list[str]) -> dict[str, list[str]]:
    """Return a mapping of function ARN -> list of exposure kinds.

    Functions with no exposure signals map to an empty list, meaning no untrusted caller
    can reach them directly.
    """
    client = session.client("lambda")
    exposures: dict[str, list[str]] = {}

    for arn in function_arns:
        found: list[str] = []
        found.extend(_function_url_exposure(client, arn))
        found.extend(_resource_policy_exposure(client, arn))
        found.extend(_event_source_exposure(client, arn))
        exposures[arn] = sorted(set(found))

    exposed = sum(1 for v in exposures.values() if v)
    unauth = sum(
        1 for v in exposures.values() if UNAUTHENTICATED_EXPOSURES.intersection(v)
    )
    logger.info(
        "Lambda exposure: %d/%d have any exposure signal, %d reachable unauthenticated",
        exposed,
        len(exposures),
        unauth,
    )
    return exposures


def _function_url_exposure(client: Any, arn: str) -> list[str]:
    """A Function URL with AuthType NONE is callable by anyone over HTTPS."""
    try:
        response = client.get_function_url_config(FunctionName=arn)
    except Exception:
        return []
    if response.get("AuthType") == "NONE":
        return [EXPOSURE_PUBLIC_FUNCTION_URL]
    return []


def _resource_policy_exposure(client: Any, arn: str) -> list[str]:
    """Inspect the resource-based policy for principals that imply an external caller."""
    try:
        response = client.get_policy(FunctionName=arn)
    except Exception:
        return []

    try:
        policy = json.loads(response.get("Policy", "{}"))
    except (ValueError, TypeError):
        return []

    found: list[str] = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        for principal in _iter_principals(stmt.get("Principal")):
            if principal == "*":
                found.append(EXPOSURE_WILDCARD_PRINCIPAL)
            elif principal in _FRONT_DOOR_SERVICES:
                found.append(_FRONT_DOOR_SERVICES[principal])

    return found


def _iter_principals(principal: Any) -> list[str]:
    """Normalise the many shapes the Principal field can take."""
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        return [p for p in principal if isinstance(p, str)]
    if isinstance(principal, dict):
        values: list[str] = []
        for key in ("AWS", "Service", "Federated"):
            entry = principal.get(key)
            if isinstance(entry, str):
                values.append(entry)
            elif isinstance(entry, list):
                values.extend(p for p in entry if isinstance(p, str))
        return values
    return []


def _event_source_exposure(client: Any, arn: str) -> list[str]:
    """An event source mapping means something upstream can trigger the function.

    This is weaker than a front door: it only matters if an attacker can write to the
    upstream queue, stream or bucket, which this does not attempt to determine.
    """
    try:
        paginator = client.get_paginator("list_event_source_mappings")
        for page in paginator.paginate(FunctionName=arn):
            if page.get("EventSourceMappings"):
                return [EXPOSURE_EVENT_SOURCE]
    except Exception:
        return []
    return []
