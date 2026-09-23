"""Gate 1: the deployable composition, run as a process would run it.

``build_served_app`` is what a deployment starts. These cases run its lifespan through a real
event loop: startup through the launcher gate, serving, periodic runtime refresh, and a drained,
retired shutdown that the next process starts after. The transport is synthetic and in-process.
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lucy.shared_execution.api import PATH, ApiRelease
from lucy.shared_execution.auth import WorkloadIdentity
from lucy.shared_execution.idempotency import IdempotencyDigestRing
from lucy.shared_execution.postgres_ledger import LedgerScope
from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    RecoveryAnchorKey,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
)
from lucy.shared_execution.served_app import ServedConfiguration, build_served_app
from lucy.shared_execution.served_startup import ServedStartupRefused
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate1_served_api import (
    DIGEST_KEY,
    RELEASE,
    _CountingTransport,
    _error,
    _record_rows,
)
from tests.integration.test_tiamat_gate1a_execution import (
    _bind_checkpoint,
    _Environment,
    _established_anchor_with_validity,
    _gate_state,
    _identity,
    _ledger,
    _seed_environment,
    _unblock,
)
from tests.integration.tiamat_signed_trust import (
    AUTHORITY_ISSUER,
    ROOT_KEY_ID,
    SignedProfile,
    SyntheticReleaseTrust,
    install_signed_authority,
)
from tests.unit.test_shared_execution_api_rc1 import (
    ISSUER,
    KEY_ID,
    PROFILE,
    SUBJECT,
    body,
    headers,
)


@pytest.fixture
def signed_process(
    disposable_roles: DisposableRoles,
) -> tuple[_Environment, SyntheticReleaseTrust]:
    """A throwaway environment whose profile, policy and grant are genuinely signed releases."""

    environment = f"g1p-{uuid4().hex[:8]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        ledger_row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert ledger_row is not None
    scope = LedgerScope(
        issuer="stoin:control",
        caller_id=f"caller-{uuid4().hex[:8]}",
        realm="g1p-realm",
        environment=environment,
        partition_id=f"partition-{uuid4().hex[:8]}",
    )
    _seed_environment(disposable_roles.recovery, environment, storage_epoch, scope)
    env = _Environment(
        owner=disposable_roles.owner,
        recovery=disposable_roles.recovery,
        runtime=disposable_roles.runtime,
        ledger_id=ledger_row[0],
        environment=environment,
        storage_epoch=storage_epoch,
        scope=scope,
        release_manager=disposable_roles.release_manager,
    )
    trust = SyntheticReleaseTrust(environment, scope.caller_id, scope.realm)
    install_signed_authority(
        trust,
        disposable_roles.release_manager,
        disposable_roles.recovery,
        SignedProfile(
            profile_id=PROFILE,
            release_id=RELEASE.release_id,
            policy_id=RELEASE.privacy_policy_id,
            policy_release_id=RELEASE.privacy_policy_release_id,
            provider_route_id=RELEASE.provider_route_id,
            rate_release_id=RELEASE.rate_release_id,
        ),
    )
    return env, trust


class _ObservedAnchor:
    """The disposable anchor, with its reads counted and an injectable verification failure."""

    def __init__(self, inner: InMemoryExternalRecoveryAnchor) -> None:
        self._inner = inner
        self.reads = 0
        self.reject_with: str | None = None

    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition:
        self.reads += 1
        if self.reject_with is not None:
            raise RecoveryAnchorRejected(self.reject_with)
        return self._inner.read(key)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _configuration(
    env: _Environment,
    trust: SyntheticReleaseTrust,
    anchor: _ObservedAnchor,
    private_key: Ed25519PrivateKey,
) -> ServedConfiguration:
    return ServedConfiguration(
        anchor=anchor,
        anchor_identity=_identity(env),
        runtime_database_url=env.runtime,
        recovery_database_url=env.recovery,
        recovery_generation=1,
        scope=env.scope,
        workload=WorkloadIdentity(
            issuer=ISSUER,
            subject=SUBJECT,
            realm="utopia-homes",
            environment=env.environment,
            keys={KEY_ID: private_key.public_key()},
            execution_profiles=frozenset({PROFILE}),
        ),
        authority_issuer=AUTHORITY_ISSUER,
        release_root_key_id=ROOT_KEY_ID,
        release_root_public_key=trust.root_public_key,
        digests=IdempotencyDigestRing(DIGEST_KEY),
        transport=_CountingTransport(),
        release=ApiRelease(execution="tiamat-gate1.1", policy=RELEASE.release_id),
        refresh_interval=timedelta(seconds=1),
    )


def _anchor(env: _Environment) -> _ObservedAnchor:
    now = datetime.now(UTC)
    inner, _ = _established_anchor_with_validity(
        env, _identity(env), _bind_checkpoint(env), now, not_after=now + timedelta(hours=1)
    )
    return _ObservedAnchor(inner)


def test_a_composed_process_serves_refreshes_retires_and_restarts(
    signed_process: tuple[_Environment, SyntheticReleaseTrust],
) -> None:
    process_env, trust = signed_process
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(process_env)
    configuration = _configuration(process_env, trust, anchor, private_key)
    raw, key = body(), uuid4()

    first = build_served_app(configuration)
    # Building the application takes no claimant; its lifespan startup does.
    assert first.process.runtime is None
    with TestClient(first.app) as client:
        assert first.runtime.launcher_invoked
        response = client.post(PATH, content=raw, headers=headers(private_key, raw, key=key))
        assert response.status_code == 200, response.text
        reads_while_serving = anchor.reads
        time.sleep(2.5)
        # The lifespan refreshed the watch from the anchor on its interval.
        assert anchor.reads >= reads_while_serving + 2
        assert first.runtime.watch.closed_reason is None

    # Shutdown drained and retired the fence without quarantining.
    ledger = _ledger(process_env)
    assert not ledger.verify_attestation_current(first.runtime.coordinator_generation)
    assert _gate_state(process_env) == (False, None)

    # The next process starts through the launcher, not by taking over, with an empty cache.
    second = build_served_app(configuration)
    with TestClient(second.app) as client:
        assert second.runtime.launcher_invoked
        assert second.runtime.coordinator_generation > first.runtime.coordinator_generation
        replay = client.post(PATH, content=raw, headers=headers(private_key, raw, key=key))
    _error(replay, 409, "idempotency_recovery_unavailable")
    assert configuration.transport.calls == 1  # type: ignore[attr-defined]
    assert len(_record_rows(process_env)) == 1


def test_a_refresh_that_finds_authority_withdrawn_closes_the_process(
    signed_process: tuple[_Environment, SyntheticReleaseTrust],
) -> None:
    process_env, trust = signed_process
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(process_env)
    configuration = _configuration(process_env, trust, anchor, private_key)
    served = build_served_app(configuration)
    raw = body()

    with TestClient(served.app) as client:
        anchor.reject_with = "recovery_anchor_signature_invalid"
        deadline = time.monotonic() + 5
        while served.runtime.watch.closed_reason is None and time.monotonic() < deadline:
            time.sleep(0.1)
        assert served.runtime.watch.closed_reason == "recovery_anchor_unverifiable"
        refused = client.post(PATH, content=raw, headers=headers(private_key, raw, key=uuid4()))
    _error(refused, 503, "state_store_unavailable")
    assert configuration.transport.calls == 0  # type: ignore[attr-defined]
    assert _record_rows(process_env) == []
    # Closing the latch also blocked the gate, so the next process cannot start without recovery.
    assert _gate_state(process_env)[0] is True
    _unblock(process_env)


def test_a_consume_only_process_serves_only_on_a_claimant_the_launcher_issued(
    signed_process: tuple[_Environment, SyntheticReleaseTrust],
) -> None:
    """The deployed shape: the server never holds the recovery credential.

    With no claimant waiting it refuses to start rather than making one. Once the separate
    launcher, which does hold the recovery credential, has issued one, the server consumes it.
    """

    env, trust = signed_process
    private_key = Ed25519PrivateKey.generate()
    anchor = _anchor(env)
    configuration = replace(
        _configuration(env, trust, anchor, private_key), recovery_database_url=None
    )

    # The recovery credential in the runtime slot is refused before anything is read.
    mislabelled = build_served_app(replace(configuration, runtime_database_url=env.recovery))
    with (
        pytest.raises(ServedStartupRefused, match="runtime_credential_is_not_the_runtime_role"),
        TestClient(mislabelled.app),
    ):
        pass

    refused = build_served_app(configuration)
    with (
        pytest.raises(ServedStartupRefused, match="startup_claimant_required"),
        TestClient(refused.app),
    ):
        pass
    assert refused.process.runtime is None

    StartupAttestationIssuer(
        anchor=anchor,
        identity=_identity(env),
        recovery_database_url=env.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(env.recovery),
    ).issue(now=datetime.now(UTC))
    served = build_served_app(configuration)
    raw = body()
    with TestClient(served.app) as client:
        assert not served.runtime.launcher_invoked
        response = client.post(PATH, content=raw, headers=headers(private_key, raw, key=uuid4()))
    assert response.status_code == 200, response.text
