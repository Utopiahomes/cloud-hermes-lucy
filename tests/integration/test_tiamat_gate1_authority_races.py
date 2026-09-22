"""Gate 1: signed-authority transitions racing each other on one subject.

Activation of a successor and revocation of the current head both lock the subject's release rows
and its head. Started together, they must serialize: one wins, the other either follows it or is
refused on a stated rule. Neither may fail as a storage error, which is what a lock-order deadlock
would surface as.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import psycopg

from lucy.shared_execution.postgres_authority import (
    AuthorityTransitionRejected,
    PostgresSignedAuthorityStore,
)
from tests.integration.test_tiamat_gate1_eligibility import (
    authority_env,  # noqa: F401 - the fixture these cases run in
)
from tests.integration.test_tiamat_gate1a_execution import (
    _authority,
    _Environment,
    _prepare_revocation,
    _stage,
)

ITERATIONS = 8


def _subject_state(env: _Environment, manager_url: str, subject: str) -> dict[str, Any]:
    with psycopg.connect(manager_url) as manager:
        manager.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        manager.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        manager.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        releases: dict[str, str] = dict(
            manager.execute(
                """
                SELECT release_id, state FROM tiamat.signed_releases
                WHERE environment = %s AND release_type = 'execution_profile'
                  AND subject_id = %s
                """,
                (env.environment, subject),
            ).fetchall()
        )
        head = manager.execute(
            """
            SELECT active_release_id, head_state FROM tiamat.release_heads
            WHERE environment = %s AND release_type = 'execution_profile' AND subject_id = %s
            """,
            (env.environment, subject),
        ).fetchone()
    return {"releases": releases, "head": head}


def test_activation_and_revocation_on_one_subject_serialize(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    env, manager = authority_env
    store = PostgresSignedAuthorityStore(manager)
    outcomes: list[tuple[str, str]] = []

    for iteration in range(ITERATIONS):
        subject = f"race-profile-{iteration}"
        first, successor = f"race-{iteration}.1", f"race-{iteration}.2"
        _stage(env, "execution_profile", subject, first, sequence=1)
        store.activate_release(_authority(env), "execution_profile", subject, first)
        _stage(
            env,
            "execution_profile",
            subject,
            successor,
            sequence=2,
            predecessor=first,
        )
        revoke = _prepare_revocation(
            env, "execution_profile", first, revocations=f"race-revocations-{iteration}"
        )
        start = threading.Barrier(2)

        def activate(
            subject: str = subject, successor: str = successor, start: Any = start
        ) -> str:
            start.wait()
            store.activate_release(_authority(env), "execution_profile", subject, successor)
            return "activated"

        def revocation(revoke: Any = revoke, start: Any = start) -> str:
            start.wait()
            try:
                revoke()
            except AuthorityTransitionRejected as exc:
                return f"revocation_refused:{exc}"
            return "revoked"

        with ThreadPoolExecutor(max_workers=2) as pool:
            activated = pool.submit(activate)
            revoked = pool.submit(revocation)
            results = (activated.result(timeout=60), revoked.result(timeout=60))
        state = _subject_state(env, manager, subject)

        if results[1] == "revoked":
            # Revocation won: the first release is revoked, and the successor then activated.
            assert state["releases"] == {first: "revoked", successor: "active"}, state
        else:
            # Activation won: the first release was no longer the head, so it could not be the
            # revocation's target.
            assert results[1] == "revocation_refused:revocation_target_not_head", results
            assert state["releases"] == {first: "superseded", successor: "active"}, state
        assert state["head"] == (successor, "active"), state
        outcomes.append(results)

    # Both orders are legitimate; what matters is that every iteration took one of them.
    assert len(outcomes) == ITERATIONS


def test_activation_and_revocation_queued_on_one_head_do_not_deadlock(
    authority_env: tuple[_Environment, str],  # noqa: F811
) -> None:
    """The interleaving that deadlocked, forced rather than hoped for.

    A third transaction holds the subject's head row. Activation starts first and queues on it;
    revocation starts next. Without a lock taken before any row, revocation would already hold
    the release row activation must supersede, while activation holds the head revocation
    needs, and the database would kill one of them. With it, revocation waits for activation
    to finish and is then refused because its target is no longer the head.
    """

    env, manager = authority_env
    store = PostgresSignedAuthorityStore(manager)
    subject, first, successor = "queued-profile", "queued.1", "queued.2"
    _stage(env, "execution_profile", subject, first, sequence=1)
    store.activate_release(_authority(env), "execution_profile", subject, first)
    _stage(env, "execution_profile", subject, successor, sequence=2, predecessor=first)
    revoke = _prepare_revocation(
        env, "execution_profile", first, revocations="queued-revocations"
    )

    with psycopg.connect(manager) as holder:
        holder.execute("SELECT set_config('tiamat.environment', %s, true)", (env.environment,))
        holder.execute("SELECT set_config('tiamat.caller_id', %s, true)", (env.scope.caller_id,))
        holder.execute("SELECT set_config('tiamat.realm', %s, true)", (env.scope.realm,))
        held = holder.execute(
            """
            SELECT 1 FROM tiamat.release_heads
            WHERE environment = %s AND release_type = 'execution_profile' AND subject_id = %s
            FOR UPDATE
            """,
            (env.environment, subject),
        ).fetchone()
        assert held is not None

        def revocation() -> str:
            try:
                revoke()
            except AuthorityTransitionRejected as exc:
                return f"revocation_refused:{exc}"
            return "revoked"

        with ThreadPoolExecutor(max_workers=2) as pool:
            activated = pool.submit(
                store.activate_release,
                _authority(env),
                "execution_profile",
                subject,
                successor,
            )
            time.sleep(2)
            revoked = pool.submit(revocation)
            time.sleep(2)
            assert not activated.done() and not revoked.done()
            holder.commit()
            activated.result(timeout=60)
            outcome = revoked.result(timeout=60)

    assert outcome == "revocation_refused:revocation_target_not_head"
    assert _subject_state(env, manager, subject) == {
        "releases": {first: "superseded", successor: "active"},
        "head": (successor, "active"),
    }
