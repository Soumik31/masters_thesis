"""IAM reachability — determines edges from IAM roles to target resources they can access."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3

from blast_radius_scanner.models import DiscoveryResult
from blast_radius_scanner.reachability.network import Edge

logger = logging.getLogger(__name__)

# Actions that grant meaningful access to resources (read or write)
INTERESTING_ACTIONS: dict[str, str] = {
    # S3
    "s3:GetObject": "s3_read",
    "s3:PutObject": "s3_write",
    "s3:DeleteObject": "s3_write",
    "s3:ListBucket": "s3_read",
    "s3:*": "s3_full",
    # DynamoDB
    "dynamodb:GetItem": "dynamodb_read",
    "dynamodb:PutItem": "dynamodb_write",
    "dynamodb:DeleteItem": "dynamodb_write",
    "dynamodb:Scan": "dynamodb_read",
    "dynamodb:Query": "dynamodb_read",
    "dynamodb:*": "dynamodb_full",
    # Lambda
    "lambda:InvokeFunction": "lambda_invoke",
    "lambda:*": "lambda_full",
    # EC2
    "ec2:*": "ec2_full",
    # RDS
    "rds-db:connect": "rds_connect",
    "rds:*": "rds_full",
    # STS (assume role = lateral movement)
    "sts:AssumeRole": "assume_role",
    # Catch-all
    "*": "full_access",
}


def discover_iam_edges(
    session: boto3.Session,
    discovery: DiscoveryResult,
    max_roles: int = 200,
) -> list[Edge]:
    """Determine IAM-based reachability from roles to target resources.

    Starts from roles attached to compute resources (EC2 instance profiles, Lambda
    execution roles) and inspects their policies to find reachable resources. When a
    policy grants sts:AssumeRole, the reached role is added to a worklist and its own
    policies are resolved in turn, so multi-hop role chains are captured. Without this
    transitive step every chain would dead-end after one hop and the graph would reduce
    to single-hop policy analysis.

    Limitations worth stating in the methodology:
    - Trust policies are not evaluated. A chain edge is emitted when the *source* role is
      granted sts:AssumeRole on a target, even if the target's trust policy would refuse
      the assumption. This over-approximates rather than under-approximates, which is the
      safer direction for a security measurement but does produce some false edges.
    - Roles reached only by chaining are not pre-added as graph nodes; they are created on
      demand by the graph builder. This keeps the blast radius denominator restricted to
      compute-attached roles plus actually-reached roles, so scores stay comparable across
      scans instead of being diluted by unrelated service-linked roles.

    Args:
        session: boto3 session for IAM API calls.
        discovery: The complete discovery result.
        max_roles: Safety cap on how many distinct roles are resolved, to bound API calls
            on accounts where a role can assume everything.
    """
    iam_client = session.client("iam")
    edges: list[Edge] = []

    # Seed the worklist with roles attached to compute resources
    worklist: list[str] = []
    for inst in discovery.ec2_instances:
        if inst.iam_role_name:
            worklist.append(inst.iam_role_name)
    for fn in discovery.lambda_functions:
        if fn.role_name:
            worklist.append(fn.role_name)

    processed: set[str] = set()
    capped = False

    while worklist:
        role_name = worklist.pop()
        if role_name in processed:
            continue
        if len(processed) >= max_roles:
            capped = True
            break
        processed.add(role_name)

        statements = _get_role_policy_statements(iam_client, role_name)
        role_edges = _match_statements_to_resources(role_name, statements, discovery)
        edges.extend(role_edges)

        # Follow role chains: any role reached becomes a new resolution target
        for edge in role_edges:
            if edge.target_id.startswith("iam_role:"):
                chained = edge.target_id.split("iam_role:", 1)[1]
                if chained not in processed:
                    worklist.append(chained)

    if capped:
        logger.warning(
            "Role resolution capped at %d roles; some chains may be truncated", max_roles
        )

    logger.info(
        "Discovered %d IAM edges across %d roles (%d chained beyond compute-attached)",
        len(edges),
        len(processed),
        max(len(processed) - _seed_role_count(discovery), 0),
    )
    return edges


def _seed_role_count(discovery: DiscoveryResult) -> int:
    """Number of distinct roles directly attached to compute resources."""
    names: set[str] = set()
    for inst in discovery.ec2_instances:
        if inst.iam_role_name:
            names.add(inst.iam_role_name)
    for fn in discovery.lambda_functions:
        if fn.role_name:
            names.add(fn.role_name)
    return len(names)


def _get_role_policy_statements(iam_client: Any, role_name: str) -> list[dict[str, Any]]:
    """Get all policy statements (inline + attached) for a role."""
    statements: list[dict[str, Any]] = []

    # 1. Inline policies
    try:
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies.get("PolicyNames", []):
            try:
                response = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                doc = response.get("PolicyDocument", {})
                if isinstance(doc, str):
                    doc = json.loads(doc)
                stmts = doc.get("Statement", [])
                statements.extend(stmts)
            except Exception as e:
                logger.debug("Could not get inline policy %s for role %s: %s", policy_name, role_name, e)
    except Exception as e:
        logger.debug("Could not list inline policies for role %s: %s", role_name, e)

    # 2. Attached managed policies
    try:
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached.get("AttachedPolicies", []):
            policy_arn = policy["PolicyArn"]
            stmts = _get_managed_policy_statements(iam_client, policy_arn)
            statements.extend(stmts)
    except Exception as e:
        logger.debug("Could not list attached policies for role %s: %s", role_name, e)

    return statements


def _get_managed_policy_statements(iam_client: Any, policy_arn: str) -> list[dict[str, Any]]:
    """Get statements from a managed policy's default version."""
    try:
        policy_info = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy_info["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        return doc.get("Statement", [])
    except Exception as e:
        logger.debug("Could not get managed policy %s: %s", policy_arn, e)
        return []


def _match_statements_to_resources(
    role_name: str,
    statements: list[dict[str, Any]],
    discovery: DiscoveryResult,
) -> list[Edge]:
    """Match IAM policy statements to discovered resources and produce edges."""
    edges: list[Edge] = []
    source_id = f"iam_role:{role_name}"

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = _normalize_list(stmt.get("Action", []))
        resources = _normalize_list(stmt.get("Resource", []))

        # Check each action against our interesting actions list
        matched_actions = _match_actions(actions)
        if not matched_actions:
            continue

        # Match resources to discovered resources
        for resource_arn in resources:
            target_edges = _resolve_resource_target(
                source_id, role_name, resource_arn, matched_actions, discovery
            )
            edges.extend(target_edges)

    return edges


def _match_actions(actions: list[str]) -> list[tuple[str, str]]:
    """Match actions against interesting actions. Returns (action, category) pairs.

    IAM actions are case-insensitive, so we normalize to lowercase for comparison.
    """
    matched: list[tuple[str, str]] = []

    for action in actions:
        action_lower = action.lower()
        # Check against all patterns (case-insensitive)
        for pattern, category in INTERESTING_ACTIONS.items():
            if _action_matches(action_lower, pattern.lower()):
                matched.append((action, category))
                break

    return matched


def _action_matches(action: str, pattern: str) -> bool:
    """Check if an action matches a pattern (supporting * wildcards)."""
    if pattern == "*":
        return True
    if action == pattern:
        return True
    # Handle wildcards like "s3:*"
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        if action.startswith(prefix):
            return True
    if action.endswith("*"):
        prefix = action[:-1]
        if pattern.startswith(prefix):
            return True
    return False


def _resolve_resource_target(
    source_id: str,
    role_name: str,
    resource_arn: str,
    matched_actions: list[tuple[str, str]],
    discovery: DiscoveryResult,
) -> list[Edge]:
    """Resolve a resource ARN to a discovered resource and create edges."""
    edges: list[Edge] = []

    if resource_arn == "*":
        # Wildcard — applies to all resources of the matched service type
        for action, category in matched_actions:
            targets = _get_wildcard_targets(category, discovery)
            for target_id in targets:
                edges.append(Edge(
                    source_id=source_id,
                    target_id=target_id,
                    edge_type="iam",
                    label=f"{action} (wildcard)",
                    details={"role": role_name, "action": action, "resource": "*"},
                ))
        return edges

    # Try matching specific ARNs to discovered resources
    for action, category in matched_actions:
        target_id = _arn_to_target_id(resource_arn, category, discovery)
        if target_id:
            edges.append(Edge(
                source_id=source_id,
                target_id=target_id,
                edge_type="iam",
                label=action,
                details={"role": role_name, "action": action, "resource": resource_arn},
            ))

    return edges


def _get_wildcard_targets(category: str, discovery: DiscoveryResult) -> list[str]:
    """Get all discovered resource IDs that match a service category."""
    targets: list[str] = []

    if category.startswith("s3"):
        targets.extend(f"s3:{b.name}" for b in discovery.s3_buckets)
    elif category.startswith("dynamodb"):
        targets.extend(f"dynamodb:{t.table_name}" for t in discovery.dynamodb_tables)
    elif category.startswith("lambda"):
        targets.extend(fn.function_arn for fn in discovery.lambda_functions)
    elif category.startswith("rds"):
        targets.extend(rds.db_instance_id for rds in discovery.rds_instances)
    elif category == "assume_role":
        # Role chaining: sts:AssumeRole on "*" can reach any role in the account
        targets.extend(f"iam_role:{name}" for name in _known_role_names(discovery))
    elif category == "full_access":
        # Full access = everything, including role chaining ("*" subsumes sts:AssumeRole)
        targets.extend(f"s3:{b.name}" for b in discovery.s3_buckets)
        targets.extend(f"dynamodb:{t.table_name}" for t in discovery.dynamodb_tables)
        targets.extend(fn.function_arn for fn in discovery.lambda_functions)
        targets.extend(rds.db_instance_id for rds in discovery.rds_instances)
        targets.extend(inst.instance_id for inst in discovery.ec2_instances)
        targets.extend(f"iam_role:{name}" for name in _known_role_names(discovery))

    return targets


def _known_role_names(discovery: DiscoveryResult) -> set[str]:
    """All role names we can resolve: account-wide if listable, else compute-attached."""
    if discovery.iam_roles:
        return set(discovery.iam_roles)
    names: set[str] = set()
    for inst in discovery.ec2_instances:
        if inst.iam_role_name:
            names.add(inst.iam_role_name)
    for fn in discovery.lambda_functions:
        if fn.role_name:
            names.add(fn.role_name)
    return names


def _arn_to_target_id(
    resource_arn: str,
    category: str,
    discovery: DiscoveryResult,
) -> str | None:
    """Try to match a resource ARN to a discovered resource's ID."""
    # S3: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/*
    if ":s3:::" in resource_arn:
        bucket_name = resource_arn.split(":::")[-1].split("/")[0]
        for bucket in discovery.s3_buckets:
            if bucket.name == bucket_name:
                return f"s3:{bucket.name}"
        return None

    # DynamoDB: arn:aws:dynamodb:region:account:table/table-name
    if ":dynamodb:" in resource_arn and ":table/" in resource_arn:
        table_name = resource_arn.split(":table/")[-1]
        for table in discovery.dynamodb_tables:
            if table.table_name == table_name:
                return f"dynamodb:{table.table_name}"
        return None

    # Lambda: arn:aws:lambda:region:account:function:function-name
    if ":lambda:" in resource_arn and ":function:" in resource_arn:
        for fn in discovery.lambda_functions:
            if fn.function_arn == resource_arn or fn.function_name in resource_arn:
                return fn.function_arn
        return None

    # IAM role: arn:aws:iam::account:role/role-name  (role chaining via sts:AssumeRole)
    if ":role/" in resource_arn:
        role_name = resource_arn.split(":role/")[-1].split("/")[-1]
        known = _known_role_names(discovery)
        if role_name in known:
            return f"iam_role:{role_name}"
        # Emit the chain edge even if the role was not enumerable, so the path is not
        # silently lost when iam:ListRoles is unavailable.
        return f"iam_role:{role_name}" if role_name else None

    # EC2 instance (rare in policies, but possible)
    if ":instance/" in resource_arn:
        instance_id = resource_arn.split(":instance/")[-1]
        for inst in discovery.ec2_instances:
            if inst.instance_id == instance_id:
                return inst.instance_id
        return None

    return None


def _normalize_list(value: Any) -> list[str]:
    """Normalize a policy field that could be a string or a list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []
