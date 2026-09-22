"""Gate 1: RC1 served through ``create_shared_execution_app`` onto the durable ledger.

Every case goes through the private HTTP surface - authentication, validation, the durable
service, the fenced executor, the disposable PostgreSQL ledger and the volatile replay cache - with
a synthetic in-process transport that reaches no network and spends nothing. Each case counts
provider requests, because the property under test is that no replay path ever makes a second.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lucy.shared_execution.api import PATH, ApiRelease, create_shared_execution_app
from lucy.shared_execution.auth import (
    InMemoryJtiReplayStore,
    WorkloadIdentity,
    WorkloadJwtVerifier,
)
from lucy.shared_execution.durable_executor import (
    DurableExecutor,
    IdempotencyRecoveryUnavailable,
)
from lucy.shared_execution.durable_service import (
    DurableExecutionService,
    ProfileCatalogue,
    ServedProfile,
    SignedProfileAuthority,
    TransportProvider,
)
from lucy.shared_execution.idempotency import DigestKey, IdempotencyDigestRing
from lucy.shared_execution.postgres_ledger import (
    LedgerScope,
    PostgresExecutionLedger,
    RecoveryWitness,
)
from lucy.shared_execution.recovery_anchor import InMemoryExternalRecoveryAnchor
from lucy.shared_execution.replay_cache import MAXIMUM_REPLAY_WINDOW, InMemoryReplayCache
from lucy.shared_execution.served_startup import ServedRuntime, start_serving
from lucy.shared_execution.service import ExecutionProfile, ProviderResult
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)
from lucy.shared_execution.wire import ExecutionRequest
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate1a_execution import (
    _activate_successor,
    _admission,
    _bind_checkpoint,
    _Environment,
    _established_anchor_with_validity,
    _identity,
    _ledger,
    _revoke,
    _seed_environment,
    _seed_signed_authority,
    _SyntheticProvider,
    _unblock,
)
from tests.integration.test_tiamat_gate1b_failures import _short_lived_fence
from tests.unit.test_shared_execution_api_rc1 import (
    ISSUER,
    KEY_ID,
    PROFILE,
    SUBJECT,
    body,
    bundle_validator,
    headers,
)

# The environment-specific idempotency secret. It survives a restart, as a deployed one would.
DIGEST_KEY = DigestKey("digest-gate1", hashlib.sha256(b"gate-1 served api").digest())
RELEASE = ServedProfile(
    profile_id=PROFILE,
    release_id="profiles-gate1.1",
    allowed_modes=frozenset({"text"}),
    maximum_output_tokens=900,
    maximum_cost_microusd=2_000,
    provider_route_id="synthetic-local",
    rate_release_id="rates.gate-1",
    eligibility_generation=1,
    deadline_ms=15_000,
    privacy_policy_id="utopia-public-zdr",
    privacy_policy_release_id="privacy-gate1.1",
)
SETTLED_MICROUSD = 137


@pytest.fixture
def served_env(disposable_roles: DisposableRoles) -> _Environment:
    """A throwaway ledger identity, spending authority and budget period per case."""

    environment = f"g1s-{uuid4().hex[:8]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        ledger_row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert ledger_row is not None
    scope = LedgerScope(
        issuer="stoin:control",
        caller_id=f"caller-{uuid4().hex[:8]}",
        realm="g1s-realm",
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
    _seed_signed_authority(
        env,
        profile=(PROFILE, RELEASE.release_id),
        policy=(RELEASE.privacy_policy_id, RELEASE.privacy_policy_release_id),
    )
    return env


class _CountingTransport:
    """Synthetic provider transport. It counts every request it receives and spends nothing."""

    def __init__(
        self, content: str | dict[str, Any] = "Candidate answer", *, hold: bool = False
    ) -> None:
        self.calls = 0
        self._content = content
        self.started = threading.Event()
        self._release = threading.Event()
        if not hold:
            self._release.set()

    def release(self) -> None:
        self._release.set()

    def execute(self, request: ExecutionRequest, profile: ExecutionProfile) -> ProviderResult:
        self.calls += 1
        self.started.set()
        assert self._release.wait(10)
        return ProviderResult(
            content=self._content,
            input_tokens=10,
            generated_tokens=4,
            output_tokens=4,
            reasoning_tokens=0,
            cost_microusd=SETTLED_MICROUSD,
        )


class _Clock:
    def __init__(self) -> None:
        self.offset = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset


@dataclass
class _Served:
    client: TestClient
    transport: _CountingTransport
    catalogue: ProfileCatalogue
    private_key: Ed25519PrivateKey
    runtime: ServedRuntime
    anchor: InMemoryExternalRecoveryAnchor
    cache: InMemoryReplayCache

    def post(self, raw: bytes, key: UUID, *, timeout_ms: int = 15_000) -> httpx.Response:
        request_headers = headers(self.private_key, raw, key=key)
        request_headers["X-Execution-Timeout-Ms"] = str(timeout_ms)
        response: httpx.Response = self.client.post(PATH, content=raw, headers=request_headers)
        return response


async def _no_delay(_started: float) -> None:
    return None


def _serve(
    env: _Environment,
    *,
    private_key: Ed25519PrivateKey,
    anchor: InMemoryExternalRecoveryAnchor | None = None,
    transport: _CountingTransport | None = None,
    cache: InMemoryReplayCache | None = None,
    catalogue: ProfileCatalogue | None = None,
    transaction_probe: Callable[[str, Any], None] | None = None,
) -> _Served:
    """One serving process, brought up the way a deployed one is.

    ``start_serving`` reads the anchor, invokes the launcher when no claimant is waiting and
    consumes exactly one. The process then holds its own fence, its runtime watch, its executor
    and its volatile cache; nothing carries over from a previous process except the ledger.
    """

    ledger = PostgresExecutionLedger(
        env.runtime,
        RecoveryWitness(
            environment=env.environment, storage_epoch=env.storage_epoch, recovery_generation=1
        ),
        transaction_probe=transaction_probe,
    )
    anchor_identity = _identity(env)
    if anchor is None:
        now = datetime.now(UTC)
        anchor, _ = _established_anchor_with_validity(
            env, anchor_identity, _bind_checkpoint(env), now, not_after=now + timedelta(hours=1)
        )
    runtime = start_serving(
        anchor=anchor,
        identity=anchor_identity,
        issuer=StartupAttestationIssuer(
            anchor=anchor,
            identity=anchor_identity,
            recovery_database_url=env.recovery,
            checkpoint_source=LedgerRecoveryCheckpointSource(env.recovery),
        ),
        ledger=ledger,
        clock=lambda: datetime.now(UTC),
    )
    transport = transport or _CountingTransport()
    catalogue = catalogue if catalogue is not None else ProfileCatalogue((RELEASE,))
    # Not ``cache or ...``: an empty cache has a length of zero and is falsy.
    if cache is None:
        cache = InMemoryReplayCache(clock=lambda: datetime.now(UTC))
    identity = WorkloadIdentity(
        issuer=ISSUER,
        subject=SUBJECT,
        realm="utopia-homes",
        environment="gate1-served",
        keys={KEY_ID: private_key.public_key()},
        execution_profiles=frozenset({PROFILE}),
    )
    executor = DurableExecutor(
        ledger=ledger,
        scope=env.scope,
        coordinator_generation=runtime.coordinator_generation,
        provider=TransportProvider(transport),
        watch=runtime.watch,
        replay_cache=cache,
    )
    service = DurableExecutionService(
        executors={SUBJECT: executor},
        profiles=SignedProfileAuthority(ledger, env.scope, catalogue),
        digests=IdempotencyDigestRing(DIGEST_KEY),
    )
    app = create_shared_execution_app(
        service,
        WorkloadJwtVerifier(identity, InMemoryJtiReplayStore()),
        ApiRelease(execution="tiamat-gate1.1", policy=RELEASE.release_id),
        authentication_failure_delay=_no_delay,
    )
    return _Served(TestClient(app), transport, catalogue, private_key, runtime, anchor, cache)


def _record_rows(env: _Environment) -> list[tuple[Any, ...]]:
    with psycopg.connect(env.recovery) as recovery:
        recovery.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        recovery.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        return recovery.execute(
            """
            SELECT execution_id, state, settlement_status, settled_microusd, failure_code
            FROM tiamat.execution_records WHERE environment = %s
            """,
            (env.environment,),
        ).fetchall()


def _error(response: httpx.Response, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    document: dict[str, Any] = response.json()
    bundle_validator("error.schema.json").validate(document)
    assert document["error"]["code"] == code
    return document


def _original(served: _Served, raw: bytes, key: UUID) -> dict[str, Any]:
    response = served.post(raw, key)
    assert response.status_code == 200, response.text
    document: dict[str, Any] = response.json()
    bundle_validator("response.schema.json").validate(document)
    assert document["replayed"] is False
    return document


def test_the_original_response_and_an_eligible_replay(served_env: _Environment) -> None:
    served = _serve(served_env, private_key=Ed25519PrivateKey.generate())
    raw, key = body(), uuid4()

    original = _original(served, raw, key)
    assert original["cost"] == {
        "reserved_microusd": 2_000,
        "settled_microusd": SETTLED_MICROUSD,
        "settlement_status": "settled",
    }
    assert original["profile_release_id"] == RELEASE.release_id

    # The one permitted retry: same body and key, fresh token and request ID.
    retry = served.post(raw, key)
    assert retry.status_code == 200, retry.text
    replayed = retry.json()
    bundle_validator("response.schema.json").validate(replayed)
    assert replayed["replayed"] is True
    assert replayed["request_id"] == retry.headers["x-request-id"] != original["request_id"]
    for member in ("execution_id", "output", "usage", "execution_profile_id", "cost"):
        assert replayed[member] == original[member]
    assert replayed["profile_release_id"] == original["profile_release_id"]
    assert served.transport.calls == 1
    assert _record_rows(served_env) == [
        (UUID(original["execution_id"]), "completed", "settled", SETTLED_MICROUSD, None)
    ]


def test_a_restart_leaves_the_completion_unrecoverable(served_env: _Environment) -> None:
    """A new process has an empty cache and a new fence; it answers 409 and runs nothing."""

    private_key = Ed25519PrivateKey.generate()
    before = _serve(served_env, private_key=private_key)
    raw, key = body(), uuid4()
    original = _original(before, raw, key)

    after = _serve(served_env, private_key=private_key, anchor=before.anchor)
    assert after.runtime.launcher_invoked
    assert after.runtime.coordinator_generation > before.runtime.coordinator_generation
    response = after.post(raw, key)

    document = _error(response, 409, "idempotency_recovery_unavailable")
    assert document["execution"] == {
        "execution_id": original["execution_id"],
        "state": "completed",
    }
    assert document["cost"] == original["cost"]
    assert "retry-after" not in response.headers
    assert (before.transport.calls, after.transport.calls) == (1, 0)
    assert len(_record_rows(served_env)) == 1


def test_an_expired_body_is_unrecoverable(served_env: _Environment) -> None:
    """Ten minutes from admission, the body is gone and the completion still stands."""

    clock = _Clock()
    served = _serve(
        served_env,
        private_key=Ed25519PrivateKey.generate(),
        cache=InMemoryReplayCache(clock=clock),
    )
    raw, key = body(), uuid4()
    original = _original(served, raw, key)

    clock.offset = MAXIMUM_REPLAY_WINDOW
    document = _error(served.post(raw, key), 409, "idempotency_recovery_unavailable")
    assert document["execution"]["execution_id"] == original["execution_id"]
    assert served.transport.calls == 1


def test_a_successor_release_invalidates_replay(served_env: _Environment) -> None:
    """RC1: activating a successor release ends replay from its predecessor, same route or not."""

    served = _serve(served_env, private_key=Ed25519PrivateKey.generate())
    raw, key = body(), uuid4()
    original = _original(served, raw, key)

    # A routine successor, activated in signed authority and known to this process.
    successor = replace(RELEASE, release_id="profiles-gate1.2")
    served.catalogue.add(successor)
    _activate_successor(
        served_env,
        "execution_profile",
        PROFILE,
        successor.release_id,
        predecessor=RELEASE.release_id,
        sequence=2,
    )
    response = served.post(raw, key)

    document = _error(response, 409, "execution_invalidated")
    assert document["execution"] == {
        "execution_id": original["execution_id"],
        "state": "completed",
    }
    assert "retry-after" not in response.headers
    assert served.transport.calls == 1


def test_a_withdrawn_profile_invalidates_replay_and_admits_nothing(
    served_env: _Environment,
) -> None:
    served = _serve(served_env, private_key=Ed25519PrivateKey.generate())
    raw, key = body(), uuid4()
    _original(served, raw, key)

    # Withdrawn in signed authority: the profile's active release is revoked.
    _revoke(served_env, "execution_profile", RELEASE.release_id)
    _error(served.post(raw, key), 409, "execution_invalidated")
    # A new key finds no record and no active release to admit one under.
    fresh = _error(served.post(raw, uuid4()), 503, "privacy_route_unavailable")
    assert "execution" not in fresh and "cost" not in fresh
    assert served.transport.calls == 1
    assert len(_record_rows(served_env)) == 1


def test_a_quarantined_route_invalidates_replay(served_env: _Environment) -> None:
    served = _serve(served_env, private_key=Ed25519PrivateKey.generate())
    raw, key = body(), uuid4()
    original = _original(served, raw, key)

    with psycopg.connect(served_env.recovery, autocommit=True) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (served_env.environment,)
        )
        recovery.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (served_env.scope.caller_id,)
        )
        recovery.execute(
            """
            INSERT INTO tiamat.route_rate_quarantines (
                environment, caller_id, realm, partition_id, provider_route_id,
                rate_release_id, reason_code, source_execution_id
            ) VALUES (%s, %s, %s, %s, %s, %s, 'cost_settlement_violation', %s)
            """,
            (
                served_env.environment,
                served_env.scope.caller_id,
                served_env.scope.realm,
                served_env.scope.partition_id,
                RELEASE.provider_route_id,
                RELEASE.rate_release_id,
                UUID(original["execution_id"]),
            ),
        )

    _error(served.post(raw, key), 409, "execution_invalidated")
    assert served.transport.calls == 1


def test_a_failed_execution_is_terminal_for_its_key(served_env: _Environment) -> None:
    """A stored failure is returned again with its receipt; the key never dispatches again."""

    served = _serve(
        served_env,
        private_key=Ed25519PrivateKey.generate(),
        # A JSON object where the request asked for text: an unusable candidate.
        transport=_CountingTransport({"unexpected": True}),
    )
    raw, key = body(), uuid4()

    first = _error(served.post(raw, key), 502, "provider_response_invalid")
    assert first["execution"]["state"] == "failed"
    assert first["cost"] == {
        "reserved_microusd": 2_000,
        "settled_microusd": SETTLED_MICROUSD,
        "settlement_status": "settled",
    }
    again = _error(served.post(raw, key), 502, "provider_response_invalid")
    assert again["execution"] == first["execution"]
    assert again["cost"] == first["cost"]
    assert served.transport.calls == 1


def test_a_duplicate_waits_then_reports_in_progress(served_env: _Environment) -> None:
    """RC1 section 11: the duplicate waits out its own ceiling, then reports the live record.

    Everything runs on one event loop. The duplicate is answered while the original is still held
    inside the provider, which it could not be if execution blocked the loop.
    """

    transport = _CountingTransport(hold=True)
    served = _serve(
        served_env,
        private_key=Ed25519PrivateKey.generate(),
        transport=transport,
    )
    raw, key = body(), uuid4()

    with served.client, ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(served.post, raw, key)
        assert transport.started.wait(10)
        waited_from = time.monotonic()
        duplicate = served.post(raw, key, timeout_ms=1_000)
        waited = time.monotonic() - waited_from
        still_running = not first.done()
        transport.release()
        original = first.result(timeout=20)

    document = _error(duplicate, 409, "request_in_progress")
    # It waited for its own one-second ceiling rather than answering at once or holding on.
    assert 0.9 <= waited < 5
    assert still_running
    assert duplicate.headers["retry-after"] == "1"
    assert document["execution"]["state"] == "dispatched"
    assert document["cost"] == {
        "reserved_microusd": 2_000,
        "settled_microusd": None,
        "settlement_status": "pending_reconciliation",
    }
    assert original.status_code == 200
    assert document["execution"]["execution_id"] == original.json()["execution_id"]
    assert transport.calls == 1


def test_a_waiting_duplicate_receives_the_outcome_it_waited_for(
    served_env: _Environment,
) -> None:
    """When the original completes inside the wait, the duplicate is the eligible replay."""

    transport = _CountingTransport(hold=True)
    served = _serve(
        served_env,
        private_key=Ed25519PrivateKey.generate(),
        transport=transport,
    )
    raw, key = body(), uuid4()

    with served.client, ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(served.post, raw, key)
        assert transport.started.wait(10)
        waiting = pool.submit(served.post, raw, key)
        # Let the duplicate find the record dispatched and begin waiting before the original ends.
        time.sleep(0.5)
        assert not waiting.done()
        transport.release()
        original = first.result(timeout=20)
        duplicate = waiting.result(timeout=20)

    assert original.status_code == 200 and duplicate.status_code == 200, duplicate.text
    replayed = duplicate.json()
    bundle_validator("response.schema.json").validate(replayed)
    assert replayed["replayed"] is True
    assert replayed["execution_id"] == original.json()["execution_id"]
    assert replayed["output"] == original.json()["output"]
    assert transport.calls == 1


def test_a_closed_latch_refuses_over_http_before_admission(served_env: _Environment) -> None:
    """Once the runtime watch closes, the served API admits nothing and reaches no provider."""

    served = _serve(served_env, private_key=Ed25519PrivateKey.generate())
    raw, key = body(), uuid4()
    completed = _original(served, raw, key)

    served.runtime.watch.close("recovery_continuity_withdrawn")
    fresh = _error(served.post(raw, uuid4()), 503, "state_store_unavailable")
    assert "execution" not in fresh and "cost" not in fresh
    # A duplicate is refused the same way: nothing is served while authority is withdrawn.
    _error(served.post(raw, key), 503, "state_store_unavailable")
    assert served.transport.calls == 1
    assert [row[0] for row in _record_rows(served_env)] == [UUID(completed["execution_id"])]
    _unblock(served_env)


def test_every_served_executor_must_hold_a_replay_cache(served_env: _Environment) -> None:
    uncached = DurableExecutor(
        ledger=_ledger(served_env),
        scope=served_env.scope,
        coordinator_generation=1,
        provider=TransportProvider(_CountingTransport()),
    )
    with pytest.raises(ValueError, match="replay cache"):
        DurableExecutionService(
            executors={SUBJECT: uncached},
            profiles=SignedProfileAuthority(
                _ledger(served_env), served_env.scope, ProfileCatalogue((RELEASE,))
            ),
            digests=IdempotencyDigestRing(DIGEST_KEY),
        )


def test_a_completion_without_a_cache_is_never_an_empty_success(
    served_env: _Environment,
) -> None:
    """Even outside the served API, a completed duplicate without a body is RC1's 409."""

    # The ledger-level admission is pinned to the Gate 1A authority, not the served profile.
    _seed_signed_authority(served_env)
    generation, _, _ = _short_lived_fence(served_env)
    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=_ledger(served_env),
        scope=served_env.scope,
        coordinator_generation=generation,
        provider=provider,
    )
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)
    first = executor.execute(admission, now=datetime.now(UTC))
    assert first.state == "completed"

    with pytest.raises(IdempotencyRecoveryUnavailable) as unavailable:
        executor.execute(admission, now=datetime.now(UTC))
    assert unavailable.value.execution_id == first.execution_id
    assert provider.dispatched_states == ["dispatched"]
