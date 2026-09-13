"""Policy admission and AWS invocation for exact-job memory outcome recovery."""

from __future__ import annotations

import http.client
import json
import re
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.chatgpt_manifest import AuthorizedPilotManifestV1
from lucy.contracts.canonical import canonical_sha256
from lucy.contracts.memory_outcome_recovery_v1 import (
    MemoryOutcomeRecoveryGrantV1,
    MemoryOutcomeRecoveryPackageV1,
    MemoryOutcomeRecoveryResultV1,
    recovery_grant_matches_package,
)
from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    Ed25519V13Signer,
    ExecutionBindingV1,
    OriginScopeV1,
    V13SigningKeyPurpose,
)
from lucy.memory_extraction import (
    MemoryExtractionDispatchV1,
    MemoryExtractionProviderOutcomeV1,
)
from lucy.memory_import import ImportManifestV2
from lucy.memory_outcome import (
    MemoryOutcomeStore,
    MemoryOutcomeUnavailable,
    memory_outcome_encryption_id,
)

MEMORY_OUTCOME_GRANT_REQUEST_PREFIX = b"LUCY-MEMORY-OUTCOME-GRANT-REQUEST-V1\0"


class MemoryOutcomeGrantRequestV1(BaseModel):
    """Content-bounded request sent from routine to the isolated policy service."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["1"] = "1"
    authorization: AuthorizedPilotManifestV1
    package: MemoryOutcomeRecoveryPackageV1

    def digest_hex(self) -> str:
        return canonical_sha256(self, prefix=MEMORY_OUTCOME_GRANT_REQUEST_PREFIX)


class MemoryOutcomeGrantAdmissionV1(BaseModel):
    """Content-free PostgreSQL admission result used as the signing clock."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    admitted_at: datetime
    authorization_expires_at: datetime
    replayed: bool


class PostgresMemoryOutcomePolicyStore:
    """Execute-only policy store; it cannot enumerate or load outcome ciphertext."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    @staticmethod
    def _request(
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeGrantRequestV1:
        return MemoryOutcomeGrantRequestV1(
            authorization=authorization,
            package=package,
        )

    def admit(
        self,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeGrantAdmissionV1:
        request = self._request(authorization, package)
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.admit_memory_outcome_recovery_v1("
                        "CAST(:authorization AS jsonb),CAST(:package AS jsonb),"
                        ":package_digest,:request_digest)"
                    ),
                    {
                        "authorization": json.dumps(
                            authorization.model_dump(mode="json"),
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        "package": json.dumps(
                            package.model_dump(mode="json"),
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        "package_digest": package.digest_hex(),
                        "request_digest": request.digest_hex(),
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise MemoryOutcomeUnavailable("outcome policy admission unavailable") from exc
        return MemoryOutcomeGrantAdmissionV1.model_validate(value)

    def require_recoverable(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        checked_at: datetime,
        phase: str,
    ) -> None:
        if phase != "pre_grant" or checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise MemoryOutcomeUnavailable("outcome policy eligibility phase is invalid")
        self.admit(authorization, package)

    def load_grant(
        self,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeRecoveryGrantV1 | None:
        request_digest = self._request(authorization, package).digest_hex()
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text("SELECT lucy.read_memory_outcome_recovery_grant_v1(:digest)"),
                    {"digest": request_digest},
                ).scalar_one()
        except DBAPIError as exc:
            raise MemoryOutcomeUnavailable("outcome recovery grant lookup unavailable") from exc
        return None if value is None else MemoryOutcomeRecoveryGrantV1.model_validate(value)

    def record_grant(
        self,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        grant: MemoryOutcomeRecoveryGrantV1,
    ) -> MemoryOutcomeRecoveryGrantV1:
        request_digest = self._request(authorization, package).digest_hex()
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.record_memory_outcome_recovery_grant_v1("
                        ":request_digest,:grant_digest,CAST(:grant AS jsonb))"
                    ),
                    {
                        "request_digest": request_digest,
                        "grant_digest": grant.unsigned_digest_hex(),
                        "grant": json.dumps(
                            grant.model_dump(mode="json"),
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise MemoryOutcomeUnavailable("outcome recovery grant storage unavailable") from exc
        stored = MemoryOutcomeRecoveryGrantV1.model_validate(value)
        if not recovery_grant_matches_package(stored, package):
            raise MemoryOutcomeUnavailable("stored recovery grant differs from package")
        return stored


class DurableMemoryOutcomeGrantIssuer:
    """Issue once through PostgreSQL, returning the winning grant on concurrent replay."""

    def __init__(
        self,
        store: PostgresMemoryOutcomePolicyStore,
        policy: MemoryOutcomeRecoveryPolicy,
    ) -> None:
        self._store = store
        self._policy = policy

    def issue(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        now: datetime,
        max_plaintext_bytes: int = 1_048_576,
    ) -> MemoryOutcomeRecoveryGrantV1:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("recovery grant request time must be timezone-aware")
        admission = self._store.admit(authorization, package)
        existing = self._store.load_grant(authorization, package)
        if existing is not None:
            if not recovery_grant_matches_package(existing, package):
                raise MemoryOutcomeUnavailable("replayed recovery grant differs from package")
            return existing
        grant = self._policy.issue(
            authorization=authorization,
            package=package,
            now=admission.admitted_at,
            max_plaintext_bytes=max_plaintext_bytes,
        )
        return self._store.record_grant(authorization, package, grant)


class HttpMemoryOutcomeGrantIssuer:
    """Routine-side private policy client; caller cannot select destination or signing data."""

    def __init__(self, hostport: str, token: str, *, timeout_seconds: int = 15) -> None:
        match = re.fullmatch(
            r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})", hostport
        )
        if match is None or not token or timeout_seconds not in range(1, 31):
            raise ValueError("private outcome policy client configuration is invalid")
        self._host = match.group(1)
        self._port = int(match.group(2))
        if self._port > 65_535:
            raise ValueError("private outcome policy client port is invalid")
        self._token = token
        self._timeout = timeout_seconds

    def issue(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        now: datetime,
        max_plaintext_bytes: int = 1_048_576,
    ) -> MemoryOutcomeRecoveryGrantV1:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("recovery grant request time must be timezone-aware")
        if max_plaintext_bytes != 1_048_576:
            raise ValueError("remote recovery plaintext limit is policy selected")
        request = MemoryOutcomeGrantRequestV1(
            authorization=authorization,
            package=package,
        )
        body = json.dumps(
            request.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(body) > 4_000_000:
            raise MemoryOutcomeUnavailable("outcome grant request is too large")
        connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(
                "POST",
                "/internal/v3/security/memory-outcomes/recovery-grant",
                body=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = connection.getresponse()
            raw = response.read(262_145)
        except (OSError, http.client.HTTPException) as exc:
            raise MemoryOutcomeUnavailable("outcome policy service is unavailable") from exc
        finally:
            connection.close()
        if response.status != 200 or len(raw) > 262_144:
            raise MemoryOutcomeUnavailable("outcome policy rejected recovery")
        try:
            grant = MemoryOutcomeRecoveryGrantV1.model_validate_json(raw)
        except ValidationError as exc:
            raise MemoryOutcomeUnavailable("outcome policy response is invalid") from exc
        if not recovery_grant_matches_package(grant, package):
            raise MemoryOutcomeUnavailable("outcome policy response changed package binding")
        return grant


class MemoryOutcomeRecoveryEligibility(Protocol):
    """Database-enforced current-state check; implementations must fail closed."""

    def require_recoverable(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        checked_at: datetime,
        phase: str,
    ) -> None: ...


class MemoryOutcomeRecoveryInvoker(Protocol):
    def recover(
        self,
        grant: MemoryOutcomeRecoveryGrantV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeRecoveryResultV1: ...


class MemoryOutcomeGrantIssuer(Protocol):
    """Issue one exact grant locally or through the isolated policy service."""

    def issue(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        now: datetime,
        max_plaintext_bytes: int = 1_048_576,
    ) -> MemoryOutcomeRecoveryGrantV1: ...


class MemoryOutcomeRecoveryPolicy:
    """Issue one short-lived grant after an exact current-state eligibility check."""

    def __init__(
        self,
        signer: Ed25519V13Signer,
        eligibility: MemoryOutcomeRecoveryEligibility,
        *,
        environment: DeploymentEnvironment,
        issuer: str,
        caller_identity: str,
        target_scope: OriginScopeV1,
        execution_binding: ExecutionBindingV1,
        policy_version: int,
        operation_id_factory: Callable[[], UUID] = uuid4,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ) -> None:
        if signer.purpose != V13SigningKeyPurpose.POLICY_NOTARY:
            raise ValueError("memory outcome recovery requires the policy notary")
        if policy_version < 1 or not caller_identity.strip() or not issuer.strip():
            raise ValueError("memory outcome recovery policy configuration is invalid")
        self._signer = signer
        self._eligibility = eligibility
        self._environment = environment
        self._issuer = issuer
        self._caller_identity = caller_identity
        self._scope = target_scope
        self._binding = execution_binding
        self._policy_version = policy_version
        self._operation_id_factory = operation_id_factory
        self._nonce_factory = nonce_factory

    def issue(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        now: datetime,
        max_plaintext_bytes: int = 1_048_576,
    ) -> MemoryOutcomeRecoveryGrantV1:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("recovery grant issuance time must be timezone-aware")
        manifest = authorization.bundle.manifest
        envelope = package.envelope
        if not isinstance(manifest, ImportManifestV2):
            raise MemoryOutcomeUnavailable("outcome recovery requires an executable V2 manifest")
        if (
            "extract" not in authorization.permitted_operations
            or manifest.expires_at <= now
            or manifest.campaign_id != envelope.binding.campaign_id
            or manifest.destination_content_scope_id
            != envelope.binding.destination_content_scope_id
            or manifest.digest != envelope.binding.manifest_digest
            or package.target_scope != self._scope
            or envelope.encryption_id
            != memory_outcome_encryption_id(envelope.binding.extraction_job_id)
        ):
            raise MemoryOutcomeUnavailable("pilot authorization does not cover this outcome")
        self._eligibility.require_recoverable(
            authorization=authorization,
            package=package,
            checked_at=now,
            phase="pre_grant",
        )
        completion_deadline = min(
            manifest.expires_at,
            now + timedelta(minutes=5),
        )
        claim_deadline = min(
            now + timedelta(seconds=60),
            completion_deadline - timedelta(microseconds=1),
        )
        if claim_deadline <= now:
            raise MemoryOutcomeUnavailable(
                "pilot authorization expires before recovery can be claimed"
            )
        unsigned = MemoryOutcomeRecoveryGrantV1(
            key_id=self._signer.key_id,
            issuer=self._issuer,
            environment=self._environment,
            issued_at=now,
            operation_id=self._operation_id_factory(),
            caller_identity=self._caller_identity,
            target_scope=self._scope,
            execution_binding=self._binding,
            campaign_id=envelope.binding.campaign_id,
            manifest_digest=envelope.binding.manifest_digest,
            extraction_job_id=envelope.binding.extraction_job_id,
            reservation_id=envelope.binding.reservation_id,
            destination_content_scope_id=envelope.binding.destination_content_scope_id,
            encryption_id=envelope.encryption_id,
            registry_id=envelope.registry_id,
            package_digest=package.digest_hex(),
            pilot_authorization_id=authorization.owner_approval_ref,
            policy_version=self._policy_version,
            permit_claim_deadline=claim_deadline,
            execution_completion_deadline=completion_deadline,
            max_plaintext_bytes=max_plaintext_bytes,
            nonce=self._nonce_factory(),
        )
        return self._signer.sign(unsigned)


class PermitBoundMemoryOutcomeRecovery:
    """Recover one exact outcome; recheck eligibility before candidate completion."""

    def __init__(
        self,
        store: MemoryOutcomeStore,
        policy: MemoryOutcomeGrantIssuer,
        eligibility: MemoryOutcomeRecoveryEligibility,
        invoker: MemoryOutcomeRecoveryInvoker,
        *,
        authorization: AuthorizedPilotManifestV1,
        target_scope: OriginScopeV1,
        clock: Callable[[], datetime],
    ) -> None:
        self._store = store
        self._policy = policy
        self._eligibility = eligibility
        self._invoker = invoker
        self._authorization = authorization
        self._scope = target_scope
        self._clock = clock

    def load(
        self,
        *,
        manifest: ImportManifestV2,
        dispatch: MemoryExtractionDispatchV1,
        reservation_id: UUID,
    ) -> MemoryExtractionProviderOutcomeV1 | None:
        envelope = self._store.load(dispatch.extraction_job_id)
        if envelope is None:
            return None
        if (
            envelope.binding.extraction_job_id != dispatch.extraction_job_id
            or envelope.binding.reservation_id != reservation_id
            or envelope.binding.campaign_id != manifest.campaign_id
            or envelope.binding.manifest_digest != manifest.digest
            or envelope.binding.request_commitment != dispatch.request_commitment
            or envelope.binding.attempt_key != dispatch.attempt_key
            or envelope.binding.source_record_ids != dispatch.source_record_ids
        ):
            raise MemoryOutcomeUnavailable("stored provider outcome does not match the exact job")
        package = MemoryOutcomeRecoveryPackageV1(
            target_scope=self._scope,
            envelope=envelope,
        )
        now = self._clock()
        grant = self._policy.issue(
            authorization=self._authorization,
            package=package,
            now=now,
        )
        result = self._invoker.recover(grant, package)
        if result.replayed or not result.released:
            raise MemoryOutcomeUnavailable(
                "recovery release was already consumed; a fresh grant is required"
            )
        if (
            result.output is None
            or result.provider_policy_id is None
            or result.model_route is None
            or result.provider_reference_commitment is None
        ):
            raise MemoryOutcomeUnavailable("released recovery result omits provider content")
        self._eligibility.require_recoverable(
            authorization=self._authorization,
            package=package,
            checked_at=self._clock(),
            phase="pre_completion",
        )
        try:
            outcome = MemoryExtractionProviderOutcomeV1(
                output=result.output,
                billed_microusd=result.billed_microusd,
                provider_policy_id=result.provider_policy_id,
                model_route=result.model_route,
                provider_reference_commitment=result.provider_reference_commitment,
            )
        except ValidationError as exc:
            raise MemoryOutcomeUnavailable("recovered provider outcome is invalid") from exc
        if (
            result.operation_id != grant.operation_id
            or result.extraction_job_id != dispatch.extraction_job_id
            or result.package_digest != package.digest_hex()
        ):
            raise MemoryOutcomeUnavailable("recovery result changed its exact binding")
        return outcome


class AwsLambdaMemoryOutcomeRecoveryInvoker:
    """Invoke only a configured, qualified recovery alias."""

    def __init__(self, client: Any, *, alias_arn: str) -> None:
        if re.fullmatch(
            r"arn:aws(?:-us-gov|-cn)?:lambda:[a-z0-9-]+:\d{12}:"
            r"function:[A-Za-z0-9-_]{1,64}:(?!\$LATEST$)[A-Za-z0-9-_]{1,128}",
            alias_arn,
        ) is None:
            raise ValueError("outcome recovery requires a qualified Lambda alias ARN")
        self._client = client
        self._alias_arn = alias_arn

    def recover(
        self,
        grant: MemoryOutcomeRecoveryGrantV1,
        package: MemoryOutcomeRecoveryPackageV1,
    ) -> MemoryOutcomeRecoveryResultV1:
        response = self._client.invoke(
            FunctionName=self._alias_arn,
            InvocationType="RequestResponse",
            Payload=json.dumps(
                {
                    "grant": grant.model_dump(mode="json"),
                    "package": package.model_dump(mode="json"),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        if response.get("StatusCode") != 200 or response.get("FunctionError"):
            raise MemoryOutcomeUnavailable("outcome recovery executor failed")
        stream = response.get("Payload")
        raw = stream.read() if hasattr(stream, "read") else stream
        if not isinstance(raw, (bytes, bytearray)):
            raise MemoryOutcomeUnavailable("outcome recovery returned no response")
        try:
            payload = json.loads(bytes(raw))
            if payload.get("ok") is not True:
                raise MemoryOutcomeUnavailable("outcome recovery request was rejected")
            return MemoryOutcomeRecoveryResultV1.model_validate(payload["result"])
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise MemoryOutcomeUnavailable("outcome recovery response is invalid") from exc
