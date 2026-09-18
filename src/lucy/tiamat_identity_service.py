"""Inert staging identity workload used before Tiamat activation.

This service exposes no inference or recovery mutation endpoint. It exists only so Render assigns
an exact OIDC workload subject before AWS trust policies are provisioned.

At startup it makes one read-only AWS STS GetCallerIdentity call and logs the resulting role ARN to
the ordinary application log stream -- nothing more. This is a bounded integration proof that this
exact Render service instance assumes its intended AWS IAM role via OIDC; it never touches
DynamoDB, never signs or verifies anything, and a failed identity check is logged, not fatal, so
/healthz still serves its fixed disabled response.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from fastapi import FastAPI
from fastapi.responses import JSONResponse

logger = logging.getLogger("lucy.tiamat_identity_service")


def log_assumed_aws_identity() -> None:
    """Logs the AWS role this process assumed via its ambient credential chain (Render's OIDC
    injection in a deployed environment). Never raises: an identity-check failure is diagnostic,
    not a reason to refuse serving /healthz."""
    try:
        identity = boto3.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        logger.warning("tiamat_identity_service_sts_check_failed error=%s", exc)
        return
    logger.info(
        "tiamat_identity_service_sts_check_ok arn=%s account=%s",
        identity.get("Arn"),
        identity.get("Account"),
    )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log_assumed_aws_identity()
    yield


app = FastAPI(
    title="Tiamat staging identity",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"status": "disabled", "provider_dispatch": False},
        headers={"Cache-Control": "no-store"},
    )
