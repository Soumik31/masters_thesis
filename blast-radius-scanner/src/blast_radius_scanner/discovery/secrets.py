"""Discover Secrets Manager secrets and SSM parameters.

These are the highest-value read targets in an AWS account: a single
secretsmanager:GetSecretValue or ssm:GetParameter call typically yields database
credentials or API keys, turning a foothold into access to a data store that is otherwise
not reachable from the compromised resource.

They were previously invisible to the scanner, which understated blast radius. An RDS
instance could appear reachable while the credential needed to use it did not appear at
all, even though CDK stores RDS credentials in Secrets Manager by default.

Only metadata is read. Secret values and parameter values are never fetched.
"""

from __future__ import annotations

import logging

import boto3

logger = logging.getLogger(__name__)


def discover_secrets(session: boto3.Session) -> list[str]:
    """Return the names of all Secrets Manager secrets.

    Uses list_secrets, which returns metadata only. GetSecretValue is deliberately never
    called: the scanner must not read secret material.
    """
    names: list[str] = []
    try:
        client = session.client("secretsmanager")
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                name = secret.get("Name")
                if name:
                    names.append(name)
    except Exception as e:
        logger.warning("Could not list secrets (secret access paths will be missed): %s", e)
        return []

    logger.info("Discovered %d Secrets Manager secret(s)", len(names))
    return names


def discover_ssm_parameters(session: boto3.Session, max_parameters: int = 500) -> list[str]:
    """Return the names of SSM parameters.

    Uses describe_parameters, which returns metadata only. GetParameter is deliberately
    never called, so parameter values are not read.

    Capped because some accounts hold thousands of parameters, and every one becomes a graph
    node and therefore part of the blast radius denominator.
    """
    names: list[str] = []
    try:
        client = session.client("ssm")
        paginator = client.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param.get("Name")
                if name:
                    names.append(name)
                if len(names) >= max_parameters:
                    logger.warning(
                        "SSM parameter discovery capped at %d; blast radius denominator "
                        "excludes the remainder",
                        max_parameters,
                    )
                    return names
    except Exception as e:
        logger.warning(
            "Could not describe SSM parameters (parameter access paths will be missed): %s", e
        )
        return []

    logger.info("Discovered %d SSM parameter(s)", len(names))
    return names
