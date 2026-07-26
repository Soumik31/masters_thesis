"""Verify all imports and module connectivity."""
import sys
sys.path.insert(0, "src")

from blast_radius_scanner.models import (
    DiscoveryResult, EC2Instance, RDSInstance, S3Bucket, DynamoDBTable,
    LambdaFunction, VPCEndpoint, NATGateway, InternetGateway, RouteTable,
    Route, SecurityGroup, SecurityGroupRule,
)
print("models: OK")

from blast_radius_scanner.discovery import discover_all
from blast_radius_scanner.discovery.ec2 import discover_ec2_instances, discover_security_groups
from blast_radius_scanner.discovery.rds import discover_rds_instances
from blast_radius_scanner.discovery.s3 import discover_s3_buckets
from blast_radius_scanner.discovery.dynamodb import discover_dynamodb_tables
from blast_radius_scanner.discovery.lambda_fn import discover_lambda_functions
from blast_radius_scanner.discovery.vpc import (
    discover_vpc_endpoints, discover_nat_gateways,
    discover_internet_gateways, discover_route_tables,
)
print("discovery: OK")

from blast_radius_scanner.reachability import map_reachability
from blast_radius_scanner.reachability.network import Edge, discover_network_edges
from blast_radius_scanner.reachability.metadata import discover_metadata_edges
from blast_radius_scanner.reachability.iam import discover_iam_edges
print("reachability: OK")

from blast_radius_scanner.graph import build_attack_graph
print("graph: OK")

from blast_radius_scanner.scorer import score_blast_radius, ScoringResult, EdgeImpact
print("scorer: OK")

from blast_radius_scanner.report import format_text_report, format_json_report
print("report: OK")

from blast_radius_scanner.export import export_graph_gexf
print("export: OK")

print("\n=== ALL MODULES CONNECTED ===")
