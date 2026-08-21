"""Discover IAM roles in the account.

Roles attached to compute resources are found via EC2/Lambda discovery, but role
chaining (sts:AssumeRole) can reach roles that no compute resource uses. Those must be
enumerated separately, otherwise a chain target cannot be resolved to a known role and
the chain edge is silently dropped.
"""

from __future__ import annotations

import logging

import boto3

logger = logging.getLogger(__name__)


def discover_iam_roles(session: boto3.Session) -> list[str]:
    """Return the names of all IAM roles in the account.

    Returns an empty list if the caller lacks iam:ListRoles, so that a restricted
    principal degrades to compute-attached roles only rather than failing the scan.
    """
    role_names: list[str] = []
    try:
        iam_client = session.client("iam")
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                name = role.get("RoleName")
                if name:
                    role_names.append(name)
    except Exception as e:
        logger.warning(
            "Could not list IAM roles (role chaining will be limited to compute-attached roles): %s",
            e,
        )
        return []

    logger.info("Discovered %d IAM roles", len(role_names))
    return role_names
