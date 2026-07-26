"""Discover DynamoDB tables."""

from __future__ import annotations

import logging

import boto3

from blast_radius_scanner.models import DynamoDBTable

logger = logging.getLogger(__name__)


def discover_dynamodb_tables(session: boto3.Session) -> list[DynamoDBTable]:
    """Discover all DynamoDB tables in the region."""
    dynamodb_client = session.client("dynamodb")
    tables: list[DynamoDBTable] = []

    paginator = dynamodb_client.get_paginator("list_tables")
    for page in paginator.paginate():
        for table_name in page.get("TableNames", []):
            table = _describe_table(dynamodb_client, table_name)
            if table:
                tables.append(table)

    logger.info("Discovered %d DynamoDB tables", len(tables))
    return tables


def _describe_table(dynamodb_client, table_name: str) -> DynamoDBTable | None:
    """Describe a single DynamoDB table."""
    try:
        response = dynamodb_client.describe_table(TableName=table_name)
        info = response["Table"]
        return DynamoDBTable(
            table_name=info["TableName"],
            table_arn=info["TableArn"],
            status=info.get("TableStatus", "UNKNOWN"),
        )
    except Exception as e:
        logger.warning("Could not describe table %s: %s", table_name, e)
        return None
