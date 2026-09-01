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
    "s3:GetObjectVersion": "s3_read",
    "s3:GetObjectAcl": "s3_read",
    "s3:PutObject": "s3_write",
    "s3:PutObjectAcl": "s3_write",
    "s3:DeleteObject": "s3_write",
    "s3:DeleteObjectVersion": "s3_write",
    "s3:ListBucket": "s3_read",
    "s3:ListBucketVersions": "s3_read",
    "s3:GetBucketPolicy": "s3_read",
    "s3:*": "s3_full",
    # DynamoDB
    "dynamodb:GetItem": "dynamodb_read",
    "dynamodb:BatchGetItem": "dynamodb_read",
    "dynamodb:PutItem": "dynamodb_write",
    "dynamodb:UpdateItem": "dynamodb_write",
    "dynamodb:BatchWriteItem": "dynamodb_write",
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
    # Secrets Manager — only GetSecretValue reveals the secret material. DescribeSecret and
    # ListSecretVersionIds return metadata (name, ARN, rotation config, version IDs) and are
    # reconnaissance rather than data access, so they are deliberately not modelled.
    "secretsmanager:GetSecretValue": "secret_read",
    "secretsmanager:BatchGetSecretValue": "secret_read",
    "secretsmanager:PutSecretValue": "secret_read",
    "secretsmanager:*": "secret_full",
    # SSM Parameter Store — same reasoning; SecureString parameters hold credentials.
    "ssm:GetParameter": "parameter_read",
    "ssm:GetParameters": "parameter_read",
    "ssm:GetParametersByPath": "parameter_read",
    "ssm:GetParameterHistory": "parameter_read",
    "ssm:PutParameter": "parameter_read",
    "ssm:*": "parameter_full",
    # KMS — decryption capability. Deliberately NOT resolved to any target: kms:Decrypt on
    # its own reaches nothing, because the attacker must already be able to retrieve the
    # ciphertext. It only matters in conjunction with a retrieval permission such as
    # secretsmanager:GetSecretValue, and the model has no way to express that conjunction.
    # Treating it as reaching every secret and parameter contributed 154 spurious edges to
    # the article-generation-prod scan. Left in the map so the action is recognised and
    # recorded rather than silently unmatched.
    "kms:Decrypt": "kms_decrypt",
    "kms:*": "kms_decrypt",
    # CloudWatch Logs — reading log content is data access. Log groups routinely contain
    # request payloads, accidentally logged tokens and connection strings in stack traces.
    # Writing log lines (logs:PutLogEvents) is excluded: it yields no data to an attacker.
    "logs:FilterLogEvents": "logs_read",
    "logs:GetLogEvents": "logs_read",
    "logs:StartQuery": "logs_read",
    # Catch-all
    "*": "full_access",
}

# Synthetic node representing all CloudWatch Logs data in the account. Log groups are not
# discovered individually: an account can hold hundreds, and adding a node each would
# dominate the blast radius denominator without adding analytical value. One aggregate node
# captures the capability while keeping scores comparable across scans.
LOGS_NODE = "logs:CloudWatchLogs"


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
    account_id = _account_id_from_discovery(discovery)
    trust_cache: dict[str, set[str] | None] = {}
    dropped_chains = 0

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

        kept_edges = []
        for edge in role_edges:
            if not edge.target_id.startswith("iam_role:"):
                kept_edges.append(edge)
                continue

            # Role chaining: only keep the edge if the target's trust policy actually
            # permits this role to assume it. Without this check a wildcard
            # sts:AssumeRole grant appears to reach every role in the account, including
            # service-linked and CDK deployment roles that would refuse the assumption.
            chained = edge.target_id.split("iam_role:", 1)[1]
            if chained not in trust_cache:
                trust_cache[chained] = _get_trust_policy_principals(iam_client, chained)
            if not _trust_permits_role(trust_cache[chained], role_name, account_id):
                dropped_chains += 1
                continue

            kept_edges.append(edge)
            if chained not in processed:
                worklist.append(chained)

        edges.extend(kept_edges)

    if capped:
        logger.warning(
            "Role resolution capped at %d roles; some chains may be truncated", max_roles
        )
    if dropped_chains:
        logger.info(
            "Dropped %d chain edge(s) refused by the target role's trust policy",
            dropped_chains,
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


def _account_id_from_discovery(discovery: DiscoveryResult) -> str | None:
    """Extract the account ID from any discovered ARN, for building role ARNs."""
    for fn in discovery.lambda_functions:
        for arn in (fn.role_arn, fn.function_arn):
            parts = (arn or "").split(":")
            if len(parts) > 4 and parts[4]:
                return parts[4]
    for inst in discovery.ec2_instances:
        parts = (inst.iam_instance_profile_arn or "").split(":")
        if len(parts) > 4 and parts[4]:
            return parts[4]
    for table in discovery.dynamodb_tables:
        parts = (table.table_arn or "").split(":")
        if len(parts) > 4 and parts[4]:
            return parts[4]
    return None


def _get_trust_policy_principals(iam_client: Any, role_name: str) -> set[str] | None:
    """Principals permitted to call sts:AssumeRole on this role.

    Returns None when the trust policy cannot be read, which callers treat as "unknown"
    rather than "denied", so a missing iam:GetRole permission does not silently delete
    every chain edge.
    """
    try:
        response = iam_client.get_role(RoleName=role_name)
        doc = response["Role"]["AssumeRolePolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(doc)
    except Exception as e:
        logger.debug("Could not read trust policy for %s: %s", role_name, e)
        return None

    principals: set[str] = set()
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = _normalize_list(stmt.get("Action", []))
        if not any(
            a.lower() in ("sts:assumerole", "sts:*", "*") for a in actions
        ):
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            principals.add("*")
            continue
        if isinstance(principal, dict):
            for key in ("AWS", "Service", "Federated"):
                entry = principal.get(key)
                if isinstance(entry, str):
                    principals.add(entry)
                elif isinstance(entry, list):
                    principals.update(p for p in entry if isinstance(p, str))
        elif isinstance(principal, str):
            principals.add(principal)

    return principals


def _trust_permits_role(
    principals: set[str] | None,
    source_role_name: str,
    account_id: str | None,
) -> bool:
    """Whether a role in this account may assume a target with these trust principals.

    Accepts an exact role ARN, an account root principal (which delegates the decision to
    the source's own identity policy, and the source does hold sts:AssumeRole), or a
    wildcard. A service principal such as cloudformation.amazonaws.com does not permit a
    role to assume the target, which is what prevents CDK deployment roles from appearing
    reachable from arbitrary Lambda execution roles.

    Unknown trust policies (None) are treated as permitted, so that a missing iam:GetRole
    permission degrades to the previous over-approximating behaviour rather than silently
    removing real paths.
    """
    if principals is None:
        return True
    if "*" in principals:
        return True
    if account_id:
        if f"arn:aws:iam::{account_id}:root" in principals:
            return True
        if f"arn:aws:iam::{account_id}:role/{source_role_name}" in principals:
            return True
    # Any exact role-ARN principal naming this role, regardless of partition or path
    for p in principals:
        if p.startswith("arn:") and ":role/" in p:
            if p.split(":role/", 1)[1].split("/")[-1] == source_role_name:
                return True
    return False


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

    Two rules matter here, both of which were previously wrong:

    1. A literal ``Action: "*"`` is the only thing that counts as full access. Previously
       the ``"*"`` entry in INTERESTING_ACTIONS was reachable by *any* action, because
       ``_action_matches`` short-circuited on ``pattern == "*"``. That meant harmless
       permissions such as ``logs:PutLogEvents`` or ``cloudwatch:PutMetricData`` were
       categorised as full_access and expanded to every resource in the account. Since
       almost every execution role carries CloudWatch Logs permissions by default, nearly
       every role appeared to reach everything.
    2. Unrecognised actions are now ignored rather than assumed dangerous. This
       under-approximates by design: an action we do not model contributes no edge. That
       is the safer error for a measurement tool, because the alternative silently
       inflates every score.

    Note that ``Action: "*"`` also used to match the first map entry (``s3:GetObject``)
    via the trailing-wildcard branch, so genuine admin grants were *under*-counted. It is
    now handled explicitly before pattern matching.
    """
    matched: list[tuple[str, str]] = []

    for action in actions:
        action_lower = action.lower()

        # Literal "all actions" grant — genuine admin
        if action_lower == "*":
            matched.append((action, "full_access"))
            continue

        category = _categorise_action(action_lower)
        if category:
            matched.append((action, category))

    return matched


def _categorise_action(action_lower: str) -> str | None:
    """Return the category for an action, or None if it is not modelled.

    Exact matches take precedence over wildcard expansion, so that ``s3:*`` is categorised
    as ``s3_full`` rather than picking up ``s3_read`` from ``s3:GetObject`` purely because
    that entry appears earlier in INTERESTING_ACTIONS. Relying on dict order made the
    category depend on where a pattern happened to sit in the map.
    """
    # Pass 1: exact match
    for pattern, category in INTERESTING_ACTIONS.items():
        if pattern == "*":
            continue
        if action_lower == pattern.lower():
            return category

    # Pass 2: wildcard expansion in either direction
    for pattern, category in INTERESTING_ACTIONS.items():
        # The "*" entry is only reachable via the explicit check in _match_actions; it must
        # never act as a catch-all for actions we do not model.
        if pattern == "*":
            continue
        if _action_matches(action_lower, pattern.lower()):
            return category

    return None


def _action_matches(action: str, pattern: str) -> bool:
    """Check if an action matches a pattern (supporting * wildcards).

    Ordering matters. When the policy action itself carries a trailing wildcard, only
    patterns falling *under* that action's prefix may match. Testing the pattern's own
    wildcard as well would let ``ssm:List*`` match the pattern ``ssm:*`` — because
    ``ssm:List*`` does start with ``ssm:`` — and be scored as full parameter access. That
    inflated results badly: ``ssm:List*``, ``lambda:List*`` and ``kms:GenerateDataKey*``
    each collapsed to full service access despite granting none of it. Listing documents
    does not read parameter values, listing functions does not invoke them, and generating
    a data key does not decrypt anything.

    ``ssm:Get*`` still correctly matches ``ssm:GetParameter``, since that pattern does fall
    under the ``ssm:Get`` prefix.
    """
    if pattern == "*":
        # Only a literal all-actions grant matches. See _match_actions.
        return action == "*"
    if action == pattern:
        return True
    if action.endswith("*"):
        return pattern.startswith(action[:-1])
    if pattern.endswith("*"):
        # A service-wide pattern such as "ssm:*" describes a grant of the entire service. It
        # must not act as a catch-all for every individual action in that service:
        # ssm:ListDocuments is not parameter access, lambda:ListFunctions is not invocation,
        # and kms:GenerateDataKey is not decryption. Only an action that is itself at least
        # this broad matches; specific actions are caught by the exact-match pass, which is
        # why they have to be enumerated in INTERESTING_ACTIONS to count.
        return action == pattern or action == "*"
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
    elif category.startswith("secret"):
        targets.extend(f"secret:{name}" for name in discovery.secrets)
    elif category.startswith("parameter"):
        targets.extend(f"ssm:{name}" for name in discovery.ssm_parameters)
    elif category == "logs_read":
        targets.append(LOGS_NODE)
    elif category == "kms_decrypt":
        # No targets by design. Decryption reaches nothing on its own: the attacker must
        # already hold the ciphertext, which requires a separate retrieval permission. The
        # model cannot express that conjunction, so the conservative choice is to emit no
        # edge rather than imply access to every encrypted resource.
        return []
    elif category == "assume_role":
        # Role chaining: sts:AssumeRole on "*" can reach any assumable role in the account
        targets.extend(f"iam_role:{name}" for name in _assumable_role_names(discovery))
    elif category == "full_access":
        # Full access = everything, including role chaining ("*" subsumes sts:AssumeRole)
        targets.extend(f"s3:{b.name}" for b in discovery.s3_buckets)
        targets.extend(f"dynamodb:{t.table_name}" for t in discovery.dynamodb_tables)
        targets.extend(fn.function_arn for fn in discovery.lambda_functions)
        targets.extend(rds.db_instance_id for rds in discovery.rds_instances)
        targets.extend(inst.instance_id for inst in discovery.ec2_instances)
        targets.extend(f"secret:{name}" for name in discovery.secrets)
        targets.extend(f"ssm:{name}" for name in discovery.ssm_parameters)
        targets.append(LOGS_NODE)
        targets.extend(f"iam_role:{name}" for name in _assumable_role_names(discovery))

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


# Roles that a workload role can never assume, because their trust policies admit only a
# specific AWS service or the SSO provider. Excluding them matters because trust policies
# are not evaluated, so a wildcard sts:AssumeRole grant would otherwise appear to reach
# every role in the account, including ones no workload could ever assume.
_NON_ASSUMABLE_ROLE_PREFIXES = (
    "AWSServiceRoleFor",
    "AWSReservedSSO_",
    "aws-controltower-",
    "stacksets-exec-",
    "AWSControlTowerExecution",
    "AWSAFT",
)


def _assumable_role_names(discovery: DiscoveryResult) -> list[str]:
    """Role names a workload role could plausibly assume."""
    return [
        name
        for name in _known_role_names(discovery)
        if not name.startswith(_NON_ASSUMABLE_ROLE_PREFIXES)
    ]


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
        # Reject wildcard patterns. An ARN like arn:aws:iam::*:role/*AWSBackup* is a
        # pattern, not a role, and treating it literally created phantom nodes such as
        # "iam_role:*" and "iam_role:*AWSBackup*".
        if not role_name or "*" in role_name or "?" in role_name:
            return None
        return f"iam_role:{role_name}"

    # Secrets Manager: arn:aws:secretsmanager:region:account:secret:name-SUFFIX
    if ":secretsmanager:" in resource_arn and ":secret:" in resource_arn:
        fragment = resource_arn.split(":secret:")[-1]
        for name in discovery.secrets:
            # AWS appends a random 6-character suffix to the ARN, so match on prefix
            if fragment == name or fragment.startswith(name):
                return f"secret:{name}"
        return None

    # SSM parameter: arn:aws:ssm:region:account:parameter/name
    if ":ssm:" in resource_arn and ":parameter" in resource_arn:
        fragment = resource_arn.split(":parameter", 1)[-1].lstrip("/")
        for name in discovery.ssm_parameters:
            if name.lstrip("/") == fragment:
                return f"ssm:{name}"
        return None

    # CloudWatch Logs: any log group resolves to the aggregate logs node
    if ":logs:" in resource_arn:
        return LOGS_NODE

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
