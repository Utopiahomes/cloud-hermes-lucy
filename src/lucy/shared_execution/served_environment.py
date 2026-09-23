"""Build one deployed serving process from its environment: the uvicorn factory entry point.

    uvicorn --factory lucy.shared_execution.served_environment:create_app_from_environment \
      --host 0.0.0.0 --port "$PORT" --workers 1

Everything is required and nothing is guessed. Trust comes from a committed trust file whose
ledger identity must match an independently configured ledger ID, and from a release root whose
key must match an independently configured digest pin. Secrets - the runtime database URL and the
idempotency digest key - come only from the environment. The AWS identity is the ambient one the
platform provides; no AWS credential is read here.

Two refusals are deliberate. A serving process must never hold the recovery credential, so its
presence is a startup refusal: the launcher runs separately and this process only consumes a
claimant. And no provider transport exists yet except the synthetic one, so any other transport
setting is refused rather than defaulted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI

from lucy.shared_execution.api import ApiRelease
from lucy.shared_execution.auth import WorkloadIdentity
from lucy.shared_execution.idempotency import DigestKey, IdempotencyDigestRing
from lucy.shared_execution.postgres_ledger import LedgerScope
from lucy.shared_execution.recovery_anchor_trust import (
    AnchorTrustRejected,
    load_anchor_trust,
    verified_anchor_reader,
)
from lucy.shared_execution.served_app import ServedConfiguration, build_served_app
from lucy.shared_execution.service import ExecutionProfile, ProviderResult
from lucy.shared_execution.wire import ExecutionRequest


class ServedEnvironmentRejected(RuntimeError):
    """The environment does not describe a process that may serve; nothing starts."""


class SyntheticTransport:
    """A provider stand-in that reaches no network and reports one microdollar per call."""

    def execute(self, request: ExecutionRequest, profile: ExecutionProfile) -> ProviderResult:
        del request, profile
        return ProviderResult(
            content="synthetic staging response",
            input_tokens=1,
            generated_tokens=1,
            output_tokens=1,
            reasoning_tokens=0,
            cost_microusd=1,
        )


def served_configuration_from_environment(
    values: Mapping[str, str] | None = None, *, now: datetime | None = None
) -> ServedConfiguration:
    environment = os.environ if values is None else values

    def required(name: str) -> str:
        value = environment.get(name, "")
        if not value:
            raise ServedEnvironmentRejected(f"{name} is required")
        return value

    if environment.get("TIAMAT_RECOVERY_DATABASE_URL"):
        raise ServedEnvironmentRejected("a serving process must not hold the recovery credential")
    if required("TIAMAT_PROVIDER_TRANSPORT") != "synthetic":
        raise ServedEnvironmentRejected("only the synthetic transport exists at this gate")

    try:
        trust = load_anchor_trust(
            json.loads(Path(required("TIAMAT_ANCHOR_TRUST_PATH")).read_text(encoding="utf-8"))
        )
    except (OSError, ValueError, AnchorTrustRejected) as exc:
        raise ServedEnvironmentRejected("anchor trust is unusable") from exc
    if str(trust.identity.ledger_id) != str(UUID(required("TIAMAT_EXPECTED_LEDGER_ID"))):
        raise ServedEnvironmentRejected("anchor trust names a different ledger")
    try:
        anchor = verified_anchor_reader(
            trust, now=now or datetime.now(UTC), environment=environment
        )
    except AnchorTrustRejected as exc:
        raise ServedEnvironmentRejected(str(exc)) from exc

    try:
        workload_keys = {
            str(kid): Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded, validate=True))
            for kid, encoded in json.loads(required("TIAMAT_WORKLOAD_KEYS_JSON")).items()
        }
        release_root_raw = base64.b64decode(
            required("TIAMAT_RELEASE_ROOT_PUBLIC_KEY_B64"), validate=True
        )
        digest_key = base64.b64decode(required("TIAMAT_IDEMPOTENCY_DIGEST_KEY_B64"), validate=True)
        recovery_generation = int(required("TIAMAT_RECOVERY_GENERATION"))
        refresh_seconds = int(environment.get("TIAMAT_ANCHOR_REFRESH_SECONDS", "30"))
    except (AttributeError, binascii.Error, TypeError, ValueError) as exc:
        raise ServedEnvironmentRejected("serving configuration is malformed") from exc
    if hashlib.sha256(release_root_raw).hexdigest() != required(
        "TIAMAT_RELEASE_ROOT_PUBLIC_KEY_SHA256"
    ):
        raise ServedEnvironmentRejected("release root does not match its pin")
    if not workload_keys:
        raise ServedEnvironmentRejected("TIAMAT_WORKLOAD_KEYS_JSON names no key")

    scope = LedgerScope(
        issuer=required("TIAMAT_LEDGER_ISSUER"),
        caller_id=required("TIAMAT_CALLER_ID"),
        realm=required("TIAMAT_REALM"),
        environment=trust.identity.environment,
        partition_id=required("TIAMAT_PARTITION_ID"),
    )
    try:
        return ServedConfiguration(
            anchor=anchor,
            anchor_identity=trust.identity,
            runtime_database_url=required("TIAMAT_RUNTIME_DATABASE_URL"),
            recovery_database_url=None,
            recovery_generation=recovery_generation,
            scope=scope,
            workload=WorkloadIdentity(
                issuer=required("TIAMAT_WORKLOAD_ISSUER"),
                subject=required("TIAMAT_WORKLOAD_SUBJECT"),
                realm=required("TIAMAT_WORKLOAD_REALM"),
                environment=trust.identity.environment,
                keys=workload_keys,
                execution_profiles=frozenset(
                    item.strip()
                    for item in required("TIAMAT_EXECUTION_PROFILES").split(",")
                    if item.strip()
                ),
            ),
            authority_issuer=required("TIAMAT_AUTHORITY_ISSUER"),
            release_root_key_id=required("TIAMAT_RELEASE_ROOT_KEY_ID"),
            release_root_public_key=Ed25519PublicKey.from_public_bytes(release_root_raw),
            digests=IdempotencyDigestRing(
                DigestKey(required("TIAMAT_IDEMPOTENCY_DIGEST_KEY_VERSION"), digest_key)
            ),
            transport=SyntheticTransport(),
            release=ApiRelease(
                execution=required("TIAMAT_EXECUTION_RELEASE"),
                policy=required("TIAMAT_POLICY_RELEASE"),
            ),
            refresh_interval=timedelta(seconds=refresh_seconds),
        )
    except ValueError as exc:
        raise ServedEnvironmentRejected("serving configuration is invalid") from exc


def create_app_from_environment() -> FastAPI:
    """The uvicorn factory. Starting to serve happens in the application's lifespan."""

    return build_served_app(served_configuration_from_environment()).app
