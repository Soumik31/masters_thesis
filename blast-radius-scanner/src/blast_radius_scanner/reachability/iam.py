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
) -> list[Edge]:
    """Determine IAM-based reachability from roles to target resources.

    For each IAM role attached to a compute resource (EC2 instance profile, Lambda execution role),
    we inspect its policies to find which resources it can access.
    """
    iam_client = session.client("iam")
    edges: list[Edge] = []

    # Collect all unique role names from EC2 and Lambda
    role_names: set[str] = set()
    for inst in discovery.ec2_instances:
        if inst.iam_role_name:
            role_names.add(inst.iam_role_name)
    for fn in discovery.lambda_functions:
        if fn.role_name:
            role_names.add(fn.role_name)

    # For each role, get its effective policies and match against discovered resources
    for role_name in role_names:
        statements = _get_role_policy_statements(iam_client, role_name)
        role_edges = _match_statements_to_resources(role_name, statements, discovery)
        edges.extend(role_edges)

    logger.info("Discovered %d IAM edges", len(edges))
    return edges


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
    elif category == "full_access":
        # Full access = everything
        targets.extend(f"s3:{b.name}" for b in discovery.s3_buckets)
        targets.extend(f"dynamodb:{t.table_name}" for t in discovery.dynamodb_tables)
        targets.extend(fn.function_arn for fn in discovery.lambda_functions)
        targets.extend(rds.db_instance_id for rds in discovery.rds_instances)
        targets.extend(inst.instance_id for inst in discovery.ec2_instances)

    return targets


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
