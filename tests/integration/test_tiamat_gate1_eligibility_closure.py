"""Gate 1: eligibility cases raised in the a9c912c review, each failing closed.

- Signed authority that is absent, staged, or unknown to this process admits nothing.
- A record without its authority pins keeps its accounting but is neither dispatched nor
  delivered.
- A route quarantine or grant invalidation between admission and dispatch aborts at zero cost
  (RC1 acceptance item 84).
- A revocation between two successors is not forgotten when the later successor activates.
- A revocation release is activated and applied in one commit, never separately.

These results are separate from, and in addition to, the a9c912c evidence.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.postgres_authority import (
    AuthorityTransitionRejected,
    PostgresSignedAuthorityStore,
)
from lucy.shared_execution.postgres_ledger import DispatchBlocked
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate1_eligibility import (
    _bare_environment,
    _held,
    _record,
    authority_env,  # noqa: F401 - the fixture most cases run in
)
from tests.integration.test_tiamat_gate1_served_api import (
    RELEASE,
    SETTLED_MICROUSD,
    _error,
    _original,
    _record_rows,
    _serve,
)
from tests.integration.test_tiamat_gate1a_execution import (
    _activate_successor,
    _admission,
    _authority,
    _Environment,
    _ledger,
    _revoke,
    _seed_signed_authority,
    _stage,
)
from tests.integration.test_tiamat_gate1b_failures import _short_lived_fence
from tests.unit.test_shared_execution_api_rc1 import PROFILE, body


def _as_recovery(env: _Environment, statement: str, parameters: tuple[Any, ...]) -> None:
    with psycopg.connect(env.recovery, autocommit=True) as recovery:
        recovery.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        recovery.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        recovery.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        recovery.execute(
            "SELECT set_config('tiamat.partition_id', %s, false)", (env.scope.partition_id,)
        )
        recovery.execute(statement, parameters)


def _refused_new_key(env: _Environment) -> None:
    served = _serve(env, private_key=Ed25519PrivateKey.generate())
    refused = _error(served.post(body(), uuid4()), 503, "privacy_route_unavailable")
    assert "execution" not in refused and "cost" not in refused
    assert served.transport.calls == 0
    assert _record_rows(env) == []


# ------------------------------------------------------------------ absent or inactive authority


def test_no_signed_authority_admits_nothing(disposable_roles: DisposableRoles) -> None:
    _refused_new_key(_bare_environment(disposable_roles))


def test_staged_but_never_activated_authority_admits_nothing(
    disposable_roles: DisposableRoles,
) -> None:
    env = _bare_environment(disposable_roles)
    _stage(env, "execution_profile", PROFILE, RELEASE.release_id, sequence=1)
    _stage(
        env,
        "privacy_policy",
        RELEASE.privacy_policy_id,
        RELEASE.privacy_policy_release_id,
        sequence=1,
    )
    _refused_new_key(env)


def test_an_active_profile_with_a_staged_policy_admits_nothing(
    disposable_roles: DisposableRoles,
) -> None:
    """Refused by the service's read, and independently by the ledger's atomic admission."""

    env = _bare_environment(disposable_roles)
    _stage(env, "execution_profile", PROFILE, RELEASE.release_id, sequence=1)
    PostgresSignedAuthorityStore(env.release_manager).activate_release(
        _authority(env), "execution_profile", PROFILE, RELEASE.release_id
    )
    _stage(
        env,
        "privacy_policy",
        RELEASE.privacy_policy_id,
        RELEASE.privacy_policy_release_id,
        sequence=1,
    )
    _refused_new_key(env)

    # The ledger does not rely on the service having looked: an admission pinned to the staged
    # policy is refused inside the admission transaction.
    generation, _, _ = _short_lived_fence(env)
    admission = replace(
        _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
        execution_profile_id=PROFILE,
        profile_release_id=RELEASE.release_id,
        privacy_policy_id=RELEASE.privacy_policy_id,
        privacy_policy_release_id=RELEASE.privacy_policy_release_id,
    )
    with pytest.raises(DispatchBlocked, match="signed profile authority is not active"):
        _ledger(env).create_or_get(
            env.scope, admission, coordinator_generation=generation, now=datetime.now(UTC)
        )
    assert _record_rows(env) == []


def test_an_active_release_unknown_to_this_process_admits_nothing(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    """A successor signed authority activated, but whose parameters this process lacks."""

    env, _ = authority_env
    _activate_successor(
        env,
        "execution_profile",
        PROFILE,
        "profiles-gate1.unknown",
        predecessor=RELEASE.release_id,
        sequence=2,
    )
    _refused_new_key(env)


def test_a_signed_successor_takes_effect_without_a_local_step(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    """Activation in signed authority alone moves new admissions to the successor."""

    env, _ = authority_env
    successor = replace(RELEASE, release_id="profiles-gate1.2")
    served = _serve(env, private_key=Ed25519PrivateKey.generate())
    served.catalogue.add(successor)
    _activate_successor(
        env,
        "execution_profile",
        PROFILE,
        successor.release_id,
        predecessor=RELEASE.release_id,
        sequence=2,
    )
    document = _original(served, body(), uuid4())
    assert document["profile_release_id"] == successor.release_id


# ------------------------------------------------------------------ records without pins


def _unpin(env: _Environment, execution_id: str) -> None:
    """Make a record look as it would had it been admitted before its pins existed."""

    _as_recovery(
        env,
        """
        UPDATE tiamat.execution_records
        SET privacy_policy_id = NULL, privacy_policy_release_id = NULL,
            profile_revocation_generation = NULL, privacy_policy_revocation_generation = NULL
        WHERE execution_id = %s
        """,
        (UUID(execution_id),),
    )


def test_an_unpinned_admitted_record_is_aborted_not_dispatched(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    env, _ = authority_env
    _seed_signed_authority(env)
    ledger = _ledger(env)
    generation, _, _ = _short_lived_fence(env)
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)
    record, created = ledger.create_or_get(
        env.scope, admission, coordinator_generation=generation, now=datetime.now(UTC)
    )
    assert created
    _unpin(env, str(record.execution_id))

    aborted = ledger.dispatch(
        env.scope,
        record.execution_id,
        coordinator_generation=generation,
        record_generation=record.record_generation,
        owner_id=admission.owner_id,
    )
    assert (aborted.state, aborted.failure_code, aborted.settled_microusd) == (
        "failed",
        "execution_aborted",
        0,
    )


def test_an_unpinned_completed_record_keeps_its_accounting_and_is_not_replayed(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    env, _ = authority_env
    served = _serve(env, private_key=Ed25519PrivateKey.generate())
    raw, key = body(), uuid4()
    original = _original(served, raw, key)
    _unpin(env, original["execution_id"])

    replay = _error(served.post(raw, key), 409, "execution_invalidated")
    assert replay["cost"] == original["cost"]
    assert _record(env, original["execution_id"])[:4] == (
        "completed",
        None,
        "settled",
        SETTLED_MICROUSD,
    )
    assert served.transport.calls == 1


# ------------------------------------------------------------------ route and grant, item 84


def _aborted_before_dispatch(env: _Environment, invalidate: str, parameters: Any) -> None:
    def probe(name: str, _connection: Any) -> None:
        if name == "dispatch_before_authority_check":
            _as_recovery(env, invalidate, parameters(env))

    served = _serve(env, private_key=Ed25519PrivateKey.generate(), transaction_probe=probe)
    document = _error(served.post(body(), uuid4()), 409, "execution_aborted")
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


def test_a_route_quarantined_after_admission_aborts_before_dispatch(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    env, _ = authority_env
    _aborted_before_dispatch(
        env,
        """
        INSERT INTO tiamat.route_rate_quarantines (
            environment, caller_id, realm, partition_id, provider_route_id,
            rate_release_id, reason_code, source_execution_id
        ) VALUES (%s, %s, %s, %s, %s, %s, 'cost_settlement_violation', %s)
        """,
        lambda env: (
            env.environment,
            env.scope.caller_id,
            env.scope.realm,
            env.scope.partition_id,
            RELEASE.provider_route_id,
            RELEASE.rate_release_id,
            # The quarantine comes from another execution's overrun on the same route.
            uuid4(),
        ),
    )


def test_a_grant_revoked_after_admission_aborts_before_dispatch(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    env, _ = authority_env
    _aborted_before_dispatch(
        env,
        """
        UPDATE tiamat.grant_releases g SET revoked_at = clock_timestamp()
        FROM tiamat.spending_partitions p
        WHERE g.release_id = p.active_grant_release_id
          AND p.environment = %s AND p.caller_id = %s AND p.realm = %s
          AND p.partition_id = %s
        """,
        lambda env: (env.environment, env.scope.caller_id, env.scope.realm, env.scope.partition_id),
    )


# ------------------------------------------------------------------ A -> B -> revoke B -> C


def test_a_revocation_between_successors_is_not_forgotten(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    """Pinned to A; B succeeds A and is revoked; C then succeeds B. A must not deliver.

    After C activates, A is only ``superseded`` and the head is ``active`` again, which is all
    a state check can see. The subject's revocation generation still shows the revocation.
    """

    env, _ = authority_env
    served = _held(env)
    raw, key = body(), uuid4()
    releases = {name: replace(RELEASE, release_id=f"profiles-gate1.{name}") for name in "BC"}

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(served.post, raw, key)
        assert served.transport.started.wait(10)
        for successor in releases.values():
            served.catalogue.add(successor)
        _activate_successor(
            env,
            "execution_profile",
            PROFILE,
            releases["B"].release_id,
            predecessor=RELEASE.release_id,
            sequence=2,
        )
        _revoke(env, "execution_profile", releases["B"].release_id)
        _activate_successor(
            env,
            "execution_profile",
            PROFILE,
            releases["C"].release_id,
            predecessor=releases["B"].release_id,
            sequence=3,
        )
        served.transport.release()
        original = first.result(timeout=20)

    # The scenario is the one described: nothing in A's or the head's state shows revocation.
    with psycopg.connect(env.release_manager) as manager:
        manager.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        manager.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        manager.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        state = manager.execute(
            """
            SELECT r.state, h.head_state, h.active_release_id, h.revocation_generation
            FROM tiamat.signed_releases r
            JOIN tiamat.release_heads h
              ON h.environment = r.environment AND h.caller_id = r.caller_id
             AND h.realm = r.realm AND h.release_type = r.release_type
             AND h.subject_id = r.subject_id
            WHERE r.environment = %s AND r.release_type = 'execution_profile'
              AND r.subject_id = %s AND r.release_id = %s
            """,
            (env.environment, PROFILE, RELEASE.release_id),
        ).fetchone()
    assert state == ("superseded", "active", releases["C"].release_id, 1)

    document = _error(original, 409, "execution_invalidated")
    assert _record(env, document["execution"]["execution_id"])[:4] == (
        "failed",
        "execution_invalidated",
        "settled",
        SETTLED_MICROUSD,
    )
    assert served.transport.calls == 1


# ------------------------------------------------------------------ revocation is one commit


def test_a_revocation_release_cannot_be_activated_without_being_applied(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    env, manager = authority_env
    _stage(env, "revocation", "gate1-direct", "revocation-direct", sequence=1)
    with pytest.raises(
        AuthorityTransitionRejected, match="revocation_requires_activate_revocation"
    ):
        PostgresSignedAuthorityStore(manager).activate_release(
            _authority(env), "revocation", "gate1-direct", "revocation-direct"
        )

