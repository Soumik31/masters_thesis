"""Auto entry point selection — ranks compute resources by exposure score."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field

from blast_radius_scanner.discovery.exposure import (
    EXPOSURE_API_GATEWAY,
    EXPOSURE_EVENT_SOURCE,
    EXPOSURE_INTERNET_FACING_LB,
    EXPOSURE_LOAD_BALANCER,
    EXPOSURE_PUBLIC_FUNCTION_URL,
    EXPOSURE_WILDCARD_PRINCIPAL,
    UNAUTHENTICATED_EXPOSURES,
)
from blast_radius_scanner.models import (
    DiscoveryResult,
    EC2Instance,
    LambdaFunction,
    RouteTable,
    SecurityGroup,
)

logger = logging.getLogger(__name__)


@dataclass
class EntryPointCandidate:
    """A compute resource scored as a potential entry point."""

    resource_id: str
    resource_type: str  # "ec2" or "lambda"
    name: str
    score: int  # 0-100
    reasons: list[str] = field(default_factory=list)
    exposures: list[str] = field(default_factory=list)

    @property
    def is_externally_reachable(self) -> bool:
        """Whether an untrusted caller can reach this resource without credentials.

        For EC2 this means a public IP. For Lambda it means a public Function URL or a
        resource policy allowing any principal. API Gateway and event sources are recorded
        as exposures but not counted here, because the API may require authentication and
        writing to an event source may itself need access.
        """
        return bool(UNAUTHENTICATED_EXPOSURES.intersection(self.exposures))


def select_entry_point(
    discovery: DiscoveryResult,
    edges: list | None = None,
    include_stopped: bool = False,
    exposed_only: bool = False,
) -> list[EntryPointCandidate]:
    """Analyze all compute resources and rank them by exposure score.

    Scoring criteria (max 100 points):
    - Internet-facing (public IP): +25
    - Internet route (NAT/IGW in subnet route table): +20
    - IMDSv1 enabled (HttpTokens=optional): +20
    - Broad SG egress (0.0.0.0/0 rule): +15
    - IAM role breadth: up to +40

    Role breadth is measured from the reachability edge list when supplied: the number of
    distinct resources the attached role can act on. That is a direct measure of privilege
    rather than a proxy. Without `edges` it falls back to counting how many resources share
    the role, which cannot differentiate functions and left every Lambda tied at the same
    score.

    Args:
        discovery: Discovery result.
        edges: Optional reachability edges, used to measure role breadth.
        include_stopped: Include EC2 instances that are not running.
        exposed_only: Return only candidates an untrusted caller can reach without
            credentials. This is the set that answers "if an attacker reaches one of my
            services, how far can they spread"; without it, internal-only resources are
            treated as equally plausible starting points even though reaching them would
            already require compromising the account.

    Returns candidates sorted by score descending.
    """
    candidates: list[EntryPointCandidate] = []

    # Build subnet → route table map for internet route checks
    subnet_rt_map, main_tables = _build_subnet_route_map(discovery.route_tables)

    role_breadth = _build_role_breadth(edges) if edges else {}

    # Score EC2 instances
    for inst in discovery.ec2_instances:
        if inst.state != "running" and not include_stopped:
            continue
        candidate = _score_ec2_instance(
            inst, subnet_rt_map, main_tables, discovery, role_breadth
        )
        candidates.append(candidate)

    # Score Lambda functions
    for fn in discovery.lambda_functions:
        candidate = _score_lambda_function(fn, role_breadth)
        candidates.append(candidate)

    if exposed_only:
        candidates = [c for c in candidates if c.is_externally_reachable]

    # Sort by score descending
    candidates.sort(key=lambda c: c.score, reverse=True)

    return candidates


def _build_role_breadth(edges: list) -> dict[str, int]:
    """Count distinct resources each role can act on, keyed by role name."""
    breadth: dict[str, set[str]] = {}
    for edge in edges:
        source = getattr(edge, "source_id", "")
        if not source.startswith("iam_role:"):
            continue
        role_name = source.split("iam_role:", 1)[1]
        breadth.setdefault(role_name, set()).add(getattr(edge, "target_id", ""))
    return {role: len(targets) for role, targets in breadth.items()}


def _score_role_breadth(role_name: str | None, role_breadth: dict[str, int]) -> tuple[int, str]:
    """Score a role by how many distinct resources it can act on.

    Uses a log scale capped at 40 points rather than coarse bands, so that any difference
    in breadth produces a different score. Bands were too blunt: a role reaching 1
    resource and one reaching 5 landed on the same score, leaving functions tied and
    auto-selection effectively arbitrary. A log curve also reflects that the marginal risk
    of the 50th reachable resource is smaller than that of the 2nd.
    """
    if not role_name:
        return 0, ""
    count = role_breadth.get(role_name, 0)
    if count == 0:
        return 0, f"role reaches no discovered resources ({role_name})"

    points = min(40, round(8 * math.log2(count + 1)))
    if count > 20:
        qualifier = " (very broad)"
    elif count > 5:
        qualifier = " (broad)"
    else:
        qualifier = ""
    return points, f"role reaches {count} resource(s){qualifier}"


def _score_ec2_instance(
    inst: EC2Instance,
    subnet_rt_map: dict[str, RouteTable],
    main_tables: dict[str, RouteTable],
    discovery: DiscoveryResult,
    role_breadth: dict[str, int] | None = None,
) -> EntryPointCandidate:
    """Score an EC2 instance as a potential entry point."""
    score = 0
    reasons: list[str] = []

    # 1. Internet-facing (public IP)
    if inst.public_ip:
        score += 25
        reasons.append(f"public IP ({inst.public_ip})")

    # 2. Internet route in subnet's route table
    rt = subnet_rt_map.get(inst.subnet_id) or main_tables.get(inst.vpc_id)
    if rt and _has_internet_route(rt, discovery):
        score += 20
        reasons.append("internet egress via NAT/IGW")

    # 3. IMDSv1 enabled
    if inst.imds_http_tokens == "optional":
        score += 20
        reasons.append("IMDSv1 enabled")
    elif inst.imds_hop_limit > 1:
        score += 10
        reasons.append(f"IMDS hop_limit={inst.imds_hop_limit}")

    # 4. Broad SG egress (0.0.0.0/0)
    if _has_broad_egress(inst.security_groups):
        score += 15
        reasons.append("broad SG egress (0.0.0.0/0)")

    # 5. IAM role breadth
    if inst.iam_role_name:
        if role_breadth:
            role_score, role_reason = _score_role_breadth(inst.iam_role_name, role_breadth)
        else:
            role_score, role_reason = _score_iam_role_breadth(inst.iam_role_name, discovery)
        score += role_score
        if role_reason:
            reasons.append(role_reason)

    # Also note stopped instances so the reason string explains a low-likelihood pick
    if inst.state != "running":
        reasons.append(f"instance state={inst.state}")

    # Reachability by an untrusted caller. A public IP is direct; being registered behind an
    # internet-facing load balancer is equally reachable and is the usual pattern for a
    # private web instance, so both count.
    exposures = list(inst.exposures)
    if inst.public_ip and EXPOSURE_WILDCARD_PRINCIPAL not in exposures:
        exposures.append(EXPOSURE_WILDCARD_PRINCIPAL)
    if EXPOSURE_INTERNET_FACING_LB in exposures:
        reasons.append("behind an internet-facing load balancer")

    # Cap at 100
    score = min(score, 100)

    return EntryPointCandidate(
        resource_id=inst.instance_id,
        resource_type="ec2",
        name=inst.name or inst.instance_id,
        score=score,
        reasons=reasons,
        exposures=exposures,
    )


def _score_lambda_function(
    fn: LambdaFunction,
    role_breadth: dict[str, int] | None = None,
) -> EntryPointCandidate:
    """Score a Lambda function as a potential entry point.

    Lambdas have no public IP and no IMDS, so network-derived signals are weak. The
    discriminating factor is the execution role's breadth: compromising the function code
    yields those credentials directly from the execution environment.
    """
    score = 0
    reasons: list[str] = []

    # Lambdas are invocable (potential entry via API Gateway, event source, etc.)
    score += 10
    reasons.append("invocable function")

    # VPC-attached = can reach internal network
    if fn.vpc_id:
        score += 10
        reasons.append("VPC-attached (internal network access)")

        # Broad SG egress
        if _has_broad_egress(fn.security_groups):
            score += 10
            reasons.append("broad SG egress (0.0.0.0/0)")

    # Reachability by an untrusted caller — the precondition for this being a real entry point
    for exposure in fn.exposures:
        if exposure == EXPOSURE_PUBLIC_FUNCTION_URL:
            score += 25
            reasons.append("public Function URL (AuthType NONE)")
        elif exposure == EXPOSURE_WILDCARD_PRINCIPAL:
            score += 25
            reasons.append("resource policy allows any principal")
        elif exposure == EXPOSURE_API_GATEWAY:
            score += 10
            reasons.append("invocable via API Gateway")
        elif exposure == EXPOSURE_LOAD_BALANCER:
            score += 10
            reasons.append("invocable via load balancer")
        elif exposure == EXPOSURE_INTERNET_FACING_LB:
            score += 25
            reasons.append("behind an internet-facing load balancer")
        elif exposure == EXPOSURE_EVENT_SOURCE:
            score += 5
            reasons.append("triggered by an event source")
    if not fn.exposures:
        reasons.append("no external trigger found (internal only)")

    # Execution role breadth — the main differentiator between functions
    if fn.role_name:
        if role_breadth:
            role_score, role_reason = _score_role_breadth(fn.role_name, role_breadth)
        else:
            role_score, role_reason = 10, f"has IAM role ({fn.role_name})"
        score += role_score
        if role_reason:
            reasons.append(role_reason)

    score = min(score, 100)

    return EntryPointCandidate(
        resource_id=fn.function_arn,
        resource_type="lambda",
        name=fn.function_name,
        score=score,
        reasons=reasons,
        exposures=list(fn.exposures),
    )


def _has_broad_egress(security_groups: list[SecurityGroup]) -> bool:
    """Check if any SG has an egress rule allowing 0.0.0.0/0."""
    for sg in security_groups:
        for rule in sg.egress:
            for cidr in rule.cidr_blocks:
                if cidr in ("0.0.0.0/0", "::/0"):
                    return True
    return False


def _has_internet_route(route_table: RouteTable, discovery: DiscoveryResult) -> bool:
    """Check if a route table has a default route to the internet."""
    igw_ids = {igw.igw_id for igw in discovery.internet_gateways}
    nat_ids = {nat.nat_gateway_id for nat in discovery.nat_gateways}

    for route in route_table.routes:
        if route.destination_cidr != "0.0.0.0/0":
            continue
        if route.state != "active":
            continue
        if route.gateway_id and (route.gateway_id in igw_ids or route.gateway_id.startswith("igw-")):
            return True
        if route.nat_gateway_id and route.nat_gateway_id in nat_ids:
            return True
    return False


def _score_iam_role_breadth(role_name: str, discovery: DiscoveryResult) -> tuple[int, str]:
    """Estimate IAM role breadth based on what we know from discovery.

    We don't re-query IAM here (that happens in reachability), but we can
    check if the role is shared across multiple resources (indicating broad use).
    """
    # Count how many resources use this role
    usage_count = 0
    for inst in discovery.ec2_instances:
        if inst.iam_role_name == role_name:
            usage_count += 1
    for fn in discovery.lambda_functions:
        if fn.role_name == role_name:
            usage_count += 1

    if usage_count > 2:
        return 20, f"IAM role shared across {usage_count} resources (likely broad)"
    elif usage_count > 0:
        return 10, f"has IAM role ({role_name})"
    return 0, ""


def _build_subnet_route_map(
    route_tables: list[RouteTable],
) -> tuple[dict[str, RouteTable], dict[str, RouteTable]]:
    """Build subnet → route table and vpc → main route table maps."""
    subnet_map: dict[str, RouteTable] = {}
    main_tables: dict[str, RouteTable] = {}

    for rt in route_tables:
        if rt.is_main:
            main_tables[rt.vpc_id] = rt
        for subnet_id in rt.subnet_associations:
            subnet_map[subnet_id] = rt

    return subnet_map, main_tables
