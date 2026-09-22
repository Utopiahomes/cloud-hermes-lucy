"""Gate 1: the security/privacy eligibility recheck, fenced against revocation.

RC1 section 11 and acceptance items 80-81: a revocation activated before the completed commit
suppresses the candidate; one activated after it affects replay only; a routine successor release
lets the connected original finish and ends replay; and section 13's recheck before dispatch
aborts at zero cost. Each case goes through the served API on the disposable ledger.

The authority rows are staged directly as the release manager rather than through signature
verification, which the signed-release tests cover. Activation and revocation then run through
the real ``PostgresSignedAuthorityStore``, as the release manager, so the lock they take is the one
under test.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.postgres_authority import AuthorityScope, PostgresSignedAuthorityStore
from lucy.shared_execution.postgres_ledger import LedgerScope
from lucy.shared_execution.signed_releases import RELEASE_ADAPTER, VerifiedRelease
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate1_served_api import (
    RELEASE,
    SETTLED_MICROUSD,
    _CountingTransport,
    _error,
    _original,
    _record_rows,
    _serve,
    _Served,
)
from tests.integration.test_tiamat_gate1a_execution import _Environment, _seed_environment
from tests.unit.test_shared_execution_api_rc1 import PROFILE, body

AUTHORITY_ISSUER = "stoin-control"
REVOCATIONS = "gate1-revocations"


@pytest.fixture
def authority_env(disposable_roles: DisposableRoles) -> tuple[_Environment, str]:
    """A fresh ledger identity whose profile and privacy policy are active signed authority."""

    environment = f"g1e-{uuid4().hex[:8]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        ledger_row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert ledger_row is not None
    scope = LedgerScope(
        issuer="stoin:control",
        caller_id=f"caller-{uuid4().hex[:8]}",
        realm="g1e-realm",
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
    )
    manager = disposable_roles.release_manager
    _stage(env, manager, "execution_profile", PROFILE, RELEASE.release_id, sequence=1)
    _stage(
        env,
        manager,
        "privacy_policy",
        RELEASE.privacy_policy_id,
        RELEASE.privacy_policy_release_id,
        sequence=1,
    )
    store = PostgresSignedAuthorityStore(manager)
    store.activate_release(_authority(env), "execution_profile", PROFILE, RELEASE.release_id)
    store.activate_release(
        _authority(env),
        "privacy_policy",
        RELEASE.privacy_policy_id,
        RELEASE.privacy_policy_release_id,
    )
    return env, manager


def _authority(env: _Environment) -> AuthorityScope:
    return AuthorityScope(env.environment, AUTHORITY_ISSUER, env.scope.caller_id, env.scope.realm)


def _stage(
    env: _Environment,
    manager_url: str,
    release_type: str,
    subject_id: str,
    release_id: str,
    *,
    sequence: int,
    predecessor: str | None = None,
) -> str:
    """Stage one release row as ``stage_release`` would, without the signature it verifies."""

    exact = f"{env.environment}:{release_type}:{subject_id}:{release_id}".encode()
    digest = hashlib.sha256(exact).hexdigest()
    now = datetime.now(UTC)
    with psycopg.connect(manager_url, autocommit=True) as manager:
        manager.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        manager.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        manager.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        manager.execute(
            """
            INSERT INTO tiamat.signed_releases (
                environment, issuer, caller_id, realm, release_type, subject_id,
                release_id, sequence, predecessor_release_id, signing_key_id,
                not_before, not_after, content_digest, exact_jws, jws_sha256, state
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'release-key-gate1',
                      %s, %s, %s, %s, %s, 'staged')
            """,
            (
                env.environment,
                AUTHORITY_ISSUER,
                env.scope.caller_id,
                env.scope.realm,
                release_type,
                subject_id,
                release_id,
                sequence,
                predecessor,
                now - timedelta(hours=1),
                now + timedelta(days=1),
                digest,
                exact,
                digest,
            ),
        )
    return digest


def _revoke(env: _Environment, manager_url: str, target_type: str, target_release_id: str) -> None:
    """Activate one revocation release and apply it, as the release manager does."""

    _prepare_revocation(env, manager_url, target_type, target_release_id)()


def _prepare_revocation(
    env: _Environment, manager_url: str, target_type: str, target_release_id: str
) -> Callable[[], None]:
    """Stage and activate a revocation release now; return the step that applies it.

    Splitting them lets a race put only ``apply_revocation`` inside the window it measures, so a
    slow connection to the database cannot pass for a revocation blocked on the lock.
    """

    release_id = f"revocation-{uuid4().hex[:8]}"
    digest = _stage(env, manager_url, "revocation", REVOCATIONS, release_id, sequence=1)
    store = PostgresSignedAuthorityStore(manager_url)
    store.activate_release(_authority(env), "revocation", REVOCATIONS, release_id)
    now = datetime.now(UTC)
    payload = RELEASE_ADAPTER.validate_python(
        {
            "format_version": "1",
            "release_id": release_id,
            "subject_id": REVOCATIONS,
            "issuer": AUTHORITY_ISSUER,
            "environment": env.environment,
            "caller_id": env.scope.caller_id,
            "realm": env.scope.realm,
            "issued_at": now.isoformat(),
            "not_before": (now - timedelta(hours=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
            "sequence": 1,
            "predecessor_release_id": None,
            "content_digest": digest,
            "release_type": "revocation",
            "content": {
                "target_type": "release",
                "target_release_type": target_type,
                "target_release_id": target_release_id,
                "reason_code": "gate1_security_revocation",
                "effective_at": now.isoformat(),
                "eligibility_generation": 2,
            },
        }
    )
    revocation = VerifiedRelease(payload=payload, exact_jws=b"gate1", jws_sha256=digest)
    return lambda: store.apply_revocation(_authority(env), revocation)


def _held(env: _Environment, **options: Any) -> _Served:
    return _serve(
        env,
        private_key=Ed25519PrivateKey.generate(),
        transport=_CountingTransport(hold=True),
        **options,
    )


def _record(env: _Environment, execution_id: str) -> tuple[Any, ...]:
    with psycopg.connect(env.recovery) as recovery:
        recovery.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        recovery.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        row = recovery.execute(
            """
            SELECT state, failure_code, settlement_status, settled_microusd,
                   response_body_sha256, profile_release_id, privacy_policy_release_id
            FROM tiamat.execution_records WHERE execution_id = %s
            """,
            (UUID(execution_id),),
        ).fetchone()
    assert row is not None
    return tuple(row)


@pytest.mark.parametrize(
    ("target_type", "target_release"),
    [
        ("execution_profile", RELEASE.release_id),
        ("privacy_policy", RELEASE.privacy_policy_release_id),
    ],
)
def test_revocation_after_dispatch_before_commit_suppresses_the_candidate(
    authority_env: tuple[_Environment, str], target_type: str, target_release: str
) -> None:
    env, manager = authority_env
    served = _held(env)
    raw, key = body(), uuid4()

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(served.post, raw, key)
        assert served.transport.started.wait(10)
        # The provider has the request; the revocation commits before the completed commit.
        _revoke(env, manager, target_type, target_release)
        served.transport.release()
        original = first.result(timeout=20)

    document = _error(original, 409, "execution_invalidated")
    assert document["execution"]["state"] == "failed"
    # The charge the provider reported is settled; suppression does not make it free.
    assert document["cost"] == {
        "reserved_microusd": 2_000,
        "settled_microusd": SETTLED_MICROUSD,
        "settlement_status": "settled",
    }
    record = _record(env, document["execution"]["execution_id"])
    assert record == (
        "failed",
        "execution_invalidated",
        "settled",
        SETTLED_MICROUSD,
        None,
        RELEASE.release_id,
        RELEASE.privacy_policy_release_id,
    )
    assert len(served.cache) == 0
    again = _error(served.post(raw, key), 409, "execution_invalidated")
    assert again["execution"] == document["execution"]
    assert served.transport.calls == 1


def test_a_revocation_waiting_on_the_commit_affects_replay_only(
    authority_env: tuple[_Environment, str],
) -> None:
    """Completion holds the subject lock: a revocation arriving then must wait for the commit."""

    env, manager = authority_env
    apply = _prepare_revocation(env, manager, "execution_profile", RELEASE.release_id)
    revocation: dict[str, Future[None]] = {}
    observed: dict[str, bool] = {}
    pool = ThreadPoolExecutor(max_workers=1)

    def probe(name: str, _connection: Any) -> None:
        if name != "settlement_after_authority_check":
            return
        revocation["future"] = pool.submit(apply)
        # Observed here, asserted below: a failure raised inside the ledger's transaction would
        # be reported as whatever the service makes of it, not as this test's finding. Without
        # the lock one apply completes well inside this window; with it, it cannot until commit.
        wait([revocation["future"]], timeout=4)
        observed["blocked_by_commit"] = not revocation["future"].done()

    served = _serve(env, private_key=Ed25519PrivateKey.generate(), transaction_probe=probe)
    raw, key = body(), uuid4()
    try:
        original = _original(served, raw, key)
        revocation["future"].result(timeout=20)
    finally:
        pool.shutdown(wait=True)

    # The revocation could not commit while the completed commit held the subject lock.
    assert observed == {"blocked_by_commit": True}
    # Delivered: the completed commit came first.
    assert _record(env, original["execution_id"])[:2] == ("completed", None)
    # The revocation then committed and ends replay.
    replay = _error(served.post(raw, key), 409, "execution_invalidated")
    assert replay["execution"] == {"execution_id": original["execution_id"], "state": "completed"}
    assert served.transport.calls == 1


def test_a_revocation_committed_inside_settlement_is_seen_by_the_check(
    authority_env: tuple[_Environment, str],
) -> None:
    """The recheck reads after taking the lock, so a revocation committed just before it counts."""

    env, manager = authority_env

    def probe(name: str, _connection: Any) -> None:
        if name == "settlement_before_authority_check":
            _revoke(env, manager, "privacy_policy", RELEASE.privacy_policy_release_id)

    served = _serve(env, private_key=Ed25519PrivateKey.generate(), transaction_probe=probe)
    raw, key = body(), uuid4()
    document = _error(served.post(raw, key), 409, "execution_invalidated")
    assert _record(env, document["execution"]["execution_id"])[:2] == (
        "failed",
        "execution_invalidated",
    )
    assert served.transport.calls == 1


def test_a_routine_successor_lets_the_original_finish_and_ends_replay(
    authority_env: tuple[_Environment, str],
) -> None:
    env, manager = authority_env
    served = _held(env)
    raw, key = body(), uuid4()
    successor = replace(RELEASE, release_id="profiles-gate1.2")

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(served.post, raw, key)
        assert served.transport.started.wait(10)
        _stage(
            env,
            manager,
            "execution_profile",
            PROFILE,
            successor.release_id,
            sequence=2,
            predecessor=RELEASE.release_id,
        )
        PostgresSignedAuthorityStore(manager).activate_release(
            _authority(env), "execution_profile", PROFILE, successor.release_id
        )
        served.profiles.activate(successor)
        served.transport.release()
        original = first.result(timeout=20)

    assert original.status_code == 200, original.text
    assert original.json()["profile_release_id"] == RELEASE.release_id
    _error(served.post(raw, key), 409, "execution_invalidated")
    assert served.transport.calls == 1


def test_a_revocation_before_dispatch_aborts_at_zero_cost(
    authority_env: tuple[_Environment, str],
) -> None:
    env, manager = authority_env

    def probe(name: str, _connection: Any) -> None:
        if name == "dispatch_before_authority_check":
            _revoke(env, manager, "execution_profile", RELEASE.release_id)

    served = _serve(env, private_key=Ed25519PrivateKey.generate(), transaction_probe=probe)
    raw, key = body(), uuid4()
    document = _error(served.post(raw, key), 409, "execution_aborted")
    assert document["execution"]["state"] == "failed"
    assert document["cost"] == {
        "reserved_microusd": 2_000,
        "settled_microusd": 0,
        "settlement_status": "settled",
    }
    assert served.transport.calls == 0
    assert _record(env, document["execution"]["execution_id"])[:4] == (
        "failed",
        "execution_aborted",
        "settled",
        0,
    )
    assert len(_record_rows(env)) == 1


def test_the_serving_role_reads_but_cannot_lock_or_write_authority(
    authority_env: tuple[_Environment, str],
) -> None:
    env, _ = authority_env
    with psycopg.connect(env.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        runtime.execute("SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,))
        runtime.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        visible = runtime.execute(
            "SELECT count(*) FROM tiamat.signed_releases WHERE environment = %s",
            (env.environment,),
        ).fetchone()
        assert visible == (2,)
        runtime.execute("SELECT set_config('tiamat.caller_id', 'another-caller', false)")
        hidden = runtime.execute(
            "SELECT count(*) FROM tiamat.signed_releases WHERE environment = %s",
            (env.environment,),
        ).fetchone()
        assert hidden == (0,)
    for statement in (
        "SELECT 1 FROM tiamat.signed_releases FOR SHARE",
        "UPDATE tiamat.release_heads SET head_state = head_state",
    ):
        with (
            psycopg.connect(env.runtime) as runtime,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            runtime.execute(statement)
