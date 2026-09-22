from __future__ import annotations

import base64
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.postgres.issue_tiamat_startup_attestation_v1 import (
    StartupGateRejected,
    run_startup_gate,
)
from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import build_quarantined_bootstrap

NOW = datetime(2026, 9, 18, 21, tzinfo=UTC)
STORE = {
    "TIAMAT_RECOVERY_ANCHOR_TABLE": "stoin-staging-tiamat-recovery-anchor-v1",
    "AWS_REGION": "us-east-1",
}


def _checkpoint(identity: RecoveryAnchorIdentity) -> dict[str, object]:
    return {
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 1,
        "release_inventory": {"state": "not_installed"},
        "release_heads": [],
        "settlement_position": [],
    }


def _package(identity: RecoveryAnchorIdentity) -> dict[str, object]:
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id="tiamat-recovery-root.staging.1",
        root_private_key=Ed25519PrivateKey.generate(),
        witness_key_id="tiamat-recovery-witness.staging.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint=_checkpoint(identity),
        now=NOW,
    )
    return artifacts.public_package(identity)


class _StoredAnchor:
    """A DynamoDB client holding exactly the record the installer wrote."""

    def __init__(self, package: dict[str, object] | None) -> None:
        self.package = package

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        if self.package is None:
            return {}
        return {
            "Item": {
                "anchor_key": kwargs["Key"]["anchor_key"],
                "transition_sha256": {"S": str(self.package["transition_sha256"])},
                "transition_version": {"N": "1"},
                "transition_jws": {
                    "B": base64.b64decode(
                        str(self.package["transition_jws_b64"]), validate=True
                    )
                },
                "witness_jws": {
                    "B": base64.b64decode(str(self.package["witness_jws_b64"]), validate=True)
                },
            }
        }

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("the startup gate must never write the anchor")


def _patch_store(monkeypatch: pytest.MonkeyPatch, client: _StoredAnchor) -> None:
    monkeypatch.setattr(
        "lucy.shared_execution.recovery_anchor_dynamodb.boto3.client",
        lambda *_args, **_kwargs: client,
    )


def test_a_ledger_mismatch_refuses_before_reaching_aws(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _package(identity)
    _patch_store(monkeypatch, _StoredAnchor(package))

    with pytest.raises(StartupGateRejected, match="startup_gate_ledger_mismatch"):
        run_startup_gate(
            trust_document=package,
            recovery_database_url="postgresql://recovery@example/tiamat",
            expected_ledger_id=uuid4(),
            now=NOW,
            environment_values=STORE,
        )


def test_incomplete_trust_refuses_before_reaching_aws(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _package(identity)
    del package["root_public_key_sha256"]

    with pytest.raises(StartupGateRejected, match="trust_incomplete"):
        run_startup_gate(
            trust_document=package,
            recovery_database_url="postgresql://recovery@example/tiamat",
            expected_ledger_id=identity.ledger_id,
            now=NOW,
            environment_values=STORE,
        )


def test_an_unreachable_anchor_refuses_without_touching_the_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _package(identity)
    _patch_store(monkeypatch, _StoredAnchor(None))

    def _no_database(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("a refused anchor read must not open the ledger")

    monkeypatch.setattr(
        "lucy.shared_execution.startup_attestation.psycopg.connect", _no_database
    )

    with pytest.raises(StartupGateRejected, match="startup_attestation_authority_unavailable"):
        run_startup_gate(
            trust_document=package,
            recovery_database_url="postgresql://recovery@example/tiamat",
            expected_ledger_id=identity.ledger_id,
            now=NOW,
            environment_values=STORE,
        )


def test_a_quarantined_anchor_never_yields_a_claimant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _package(identity)
    _patch_store(monkeypatch, _StoredAnchor(package))

    class _Row:
        def __init__(self, row: dict[str, Any] | None) -> None:
            self._row = row

        def fetchone(self) -> dict[str, Any] | None:
            return self._row

    class _Connection:
        """Answer the ledger side so the refusal can only come from the anchor itself."""

        def __enter__(self) -> _Connection:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def transaction(self) -> Any:
            return nullcontext()

        def execute(self, query: str, params: Any = None) -> Any:
            normalized = " ".join(query.split())
            if "set_config" in normalized:
                return _Row(None)
            if "recovery_checkpoints" in normalized:
                return _Row(
                    {
                        "checkpoint_sha256": _checkpoint_digest(package),
                        "ledger_id": identity.ledger_id,
                        "storage_epoch": identity.storage_epoch,
                        "release_inventory": {"generation": 1, "jws_sha256": "f" * 64},
                    }
                )
            if normalized == "SELECT current_user":
                return _Row({"current_user": "tiamat_recovery"})
            if "FROM tiamat.restore_gate AS gate" in normalized:
                return _Row(
                    {
                        "storage_epoch": identity.storage_epoch,
                        "recovery_generation": 1,
                        "dispatch_blocked": False,
                        "anchor_floor_version": 0,
                        "anchor_floor_sha256": None,
                        "ledger_id": identity.ledger_id,
                    }
                )
            if "pg_control_system" in normalized:
                return _Row(
                    {
                        "system_identifier": "123",
                        "timeline_id": 1,
                        "flushed_wal_lsn": "0/200",
                    }
                )
            if "INSERT INTO tiamat.startup_attestations" in normalized:
                raise AssertionError("a quarantined anchor must not produce a claimant")
            raise AssertionError(f"unexpected query: {normalized}")

    monkeypatch.setattr(
        "lucy.shared_execution.startup_attestation.psycopg.connect",
        lambda *_args, **_kwargs: _Connection(),
    )

    # The day-zero record is quarantined, so dispatch authority is refused before any claimant
    # row is written, even though the checkpoint digest matches.
    with pytest.raises(StartupGateRejected, match="recovery_continuity_not_established"):
        run_startup_gate(
            trust_document=package,
            recovery_database_url="postgresql://recovery@example/tiamat",
            expected_ledger_id=identity.ledger_id,
            now=NOW,
            environment_values=STORE,
        )


def _checkpoint_digest(package: dict[str, object]) -> str:
    import json

    body = base64.b64decode(str(package["witness_jws_b64"]), validate=True).decode("ascii")
    payload = body.split(".")[1]
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return str(decoded["checkpoint_digest"])
