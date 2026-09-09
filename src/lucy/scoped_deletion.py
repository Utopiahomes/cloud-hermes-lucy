"""Verified admission for realm-scoped deletion manifests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.security_v1_3 import (
    DeletionTargetManifestV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
)


class ScopedDeletionUnavailable(PermissionError):
    """The manifest could not cross the verified scoped deletion boundary."""


class ScopedDeletionManifestResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    manifest_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    targets_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_count: int = Field(ge=1, le=90)
    replayed: bool


class ScopedDeletionManifestStore(Protocol):
    def store(
        self, manifest: DeletionTargetManifestV2
    ) -> ScopedDeletionManifestResult: ...


class PostgresScopedDeletionManifestStore:
    """Execute-only adapter; cryptographic admission belongs to the service above it."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def store(self, manifest: DeletionTargetManifestV2) -> ScopedDeletionManifestResult:
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.store_scoped_deletion_manifest_v2("
                        ":operation,:manifest)"
                    ),
                    {
                        "operation": manifest.operation_id,
                        "manifest": manifest.model_dump_json(),
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise ScopedDeletionUnavailable(
                "scoped deletion manifest operation is unavailable"
            ) from exc
        return ScopedDeletionManifestResult.model_validate(result)


class VerifiedScopedDeletionService:
    """Verify policy authority before the manifest reaches PostgreSQL."""

    def __init__(
        self,
        store: ScopedDeletionManifestStore,
        *,
        policy_verifier: V13ContractVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._policy_verifier = policy_verifier
        self._clock = clock or (lambda: datetime.now(UTC))

    def freeze(
        self, manifest: DeletionTargetManifestV2
    ) -> ScopedDeletionManifestResult:
        self._policy_verifier.verify(
            manifest,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=self._clock(),
        )
        result = self._store.store(manifest)
        if (
            result.manifest_id != manifest.manifest_id
            or result.manifest_digest != manifest.unsigned_digest_hex()
            or result.targets_digest != manifest.targets_digest
            or result.target_count != manifest.target_count
        ):
            raise ScopedDeletionUnavailable(
                "stored scoped deletion manifest differs from verified authority"
            )
        return result
