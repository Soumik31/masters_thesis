"""Data models representing discovered AWS resources."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityGroupRule:
    """A single ingress or egress rule within a security group."""

    protocol: str  # "tcp", "udp", "icmp", "-1" (all)
    from_port: int
    to_port: int
    cidr_blocks: list[str] = field(default_factory=list)
    source_sg_ids: list[str] = field(default_factory=list)
    prefix_list_ids: list[str] = field(default_factory=list)


@dataclass
class SecurityGroup:
    """An EC2 security group with ingress/egress rules."""

    group_id: str
    group_name: str
    vpc_id: str
    ingress: list[SecurityGroupRule] = field(default_factory=list)
    egress: list[SecurityGroupRule] = field(default_factory=list)


@dataclass
class EC2Instance:
    """A discovered EC2 instance."""

    instance_id: str
    name: str
    state: str
    vpc_id: str
    subnet_id: str
    private_ip: str | None
    public_ip: str | None
    security_groups: list[SecurityGroup] = field(default_factory=list)
    iam_instance_profile_arn: str | None = None
    iam_role_name: str | None = None
    imds_http_tokens: str = "optional"  # "optional" or "required"
    imds_hop_limit: int = 1


@dataclass
class RDSInstance:
    """A discovered RDS instance."""

    db_instance_id: str
    engine: str
    vpc_id: str | None
    subnet_ids: list[str] = field(default_factory=list)
    security_groups: list[SecurityGroup] = field(default_factory=list)
    publicly_accessible: bool = False
    endpoint: str | None = None
    port: int | None = None


@dataclass
class S3Bucket:
    """A discovered S3 bucket."""

    name: str
    region: str | None = None
    public_access_block: dict[str, bool] = field(default_factory=dict)
    policy: dict[str, Any] | None = None


@dataclass
class DynamoDBTable:
    """A discovered DynamoDB table."""

    table_name: str
    table_arn: str
    status: str


@dataclass
class LambdaFunction:
    """A discovered Lambda function."""

    function_name: str
    function_arn: str
    runtime: str | None
    role_arn: str
    role_name: str
    vpc_id: str | None = None
    subnet_ids: list[str] = field(default_factory=list)
    security_groups: list[SecurityGroup] = field(default_factory=list)
    exposures: list[str] = field(default_factory=list)


@dataclass
class VPCEndpoint:
    """A discovered VPC endpoint."""

    endpoint_id: str
    service_name: str
    vpc_id: str
    endpoint_type: str  # "Interface" or "Gateway"
    route_table_ids: list[str] = field(default_factory=list)
    subnet_ids: list[str] = field(default_factory=list)
    policy: dict[str, Any] | None = None


@dataclass
class NATGateway:
    """A discovered NAT Gateway."""

    nat_gateway_id: str
    vpc_id: str
    subnet_id: str
    public_ip: str | None = None
    state: str = "available"


@dataclass
class InternetGateway:
    """A discovered Internet Gateway."""

    igw_id: str
    vpc_ids: list[str] = field(default_factory=list)


@dataclass
class Route:
    """A single route in a route table."""

    destination_cidr: str | None = None
    destination_prefix_list_id: str | None = None
    gateway_id: str | None = None
    nat_gateway_id: str | None = None
    vpc_endpoint_id: str | None = None
    instance_id: str | None = None
    state: str = "active"


@dataclass
class RouteTable:
    """A discovered route table."""

    route_table_id: str
    vpc_id: str
    subnet_associations: list[str] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    is_main: bool = False


@dataclass
class DiscoveryResult:
    """Complete discovery result containing all resources found."""

    ec2_instances: list[EC2Instance] = field(default_factory=list)
    rds_instances: list[RDSInstance] = field(default_factory=list)
    s3_buckets: list[S3Bucket] = field(default_factory=list)
    dynamodb_tables: list[DynamoDBTable] = field(default_factory=list)
    lambda_functions: list[LambdaFunction] = field(default_factory=list)
    vpc_endpoints: list[VPCEndpoint] = field(default_factory=list)
    nat_gateways: list[NATGateway] = field(default_factory=list)
    internet_gateways: list[InternetGateway] = field(default_factory=list)
    route_tables: list[RouteTable] = field(default_factory=list)
    security_groups: dict[str, SecurityGroup] = field(default_factory=dict)
    iam_roles: list[str] = field(default_factory=list)

    @property
    def total_resources(self) -> int:
        """Total count of all discovered resources."""
        return (
            len(self.ec2_instances)
            + len(self.rds_instances)
            + len(self.s3_buckets)
            + len(self.dynamodb_tables)
            + len(self.lambda_functions)
            + len(self.vpc_endpoints)
            + len(self.nat_gateways)
            + len(self.internet_gateways)
            + len(self.route_tables)
        )
