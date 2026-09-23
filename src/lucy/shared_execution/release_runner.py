"""Control's one-off release runner: stage and activate exact pre-signed releases, verified first.

Gate 2 Proof 2 decision D4: on a disposable ledger, the narrowly granted release-manager login is
held only by a Control-operated one-off runner. The runner holds no recovery, owner, serving,
signing or AWS credential; it receives exact pre-signed bytes and independently approved public
pins. This is the authenticated local management action of Signed Release RC1 section 6, not an
online activation API.

Every operation first proves its own session: the login is ``tiamat_release_manager``, the
transport is TLS, and the ledger is the one the operator named. Immediately before a write it
re-reads the active RELEASE inventory, verifies it against the approved root pin, and verifies
the release under it now (signature, key status, applicability, scope, content digest). An
activation also requires the exact bytes to be the staged ones, the predecessor and sequence to
succeed the current head, an open gate, and, for a spending grant, active profile and policy
heads in the same scope. After a write it reads the result back. Previews write nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucy.shared_execution.postgres_authority import (
    AuthorityScope,
    PostgresSignedAuthorityStore,
)
from lucy.shared_execution.signed_releases import (
    SignedReleaseRejected,
    TrustInventory,
    VerifiedRelease,
    verify_release,
    verify_trust_inventory,
)

RELEASE_MANAGER = "tiamat_release_manager"


class ReleaseRunnerRejected(RuntimeError):
    """The runner refused; ``str(exc)`` is a content-free reason code."""


def release_root_from_pin(
    pin: object, *, environment: str, root_key_id: str, public_key_b64: str
) -> Ed25519PublicKey:
    """Authenticate a supplied RELEASE root key against the approved, committed pin.

    The pin names the environment, the root key ID and the SHA-256 of the raw public key that
    Control approved. The supplied key's own digest is computed only to compare with it.
    """

    if not isinstance(pin, dict) or set(pin) != {
        "format_version",
        "environment",
        "root_key_id",
        "root_public_key_sha256",
    }:
        raise ValueError("release root pin shape is invalid")
    if (
        pin["format_version"] != "1"
        or pin["environment"] != environment
        or pin["root_key_id"] != root_key_id
    ):
        raise ValueError("release root pin does not name this environment and root key")
    raw = base64.b64decode(public_key_b64, validate=True)
    if hashlib.sha256(raw).hexdigest() != pin["root_public_key_sha256"]:
        raise ValueError("release root public key does not match the approved pin")
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass(frozen=True)
class RunnerContext:
    """What the operator pins for one run; nothing here is read from the ledger."""

    database_url: str
    expected_ledger_id: UUID
    scope: AuthorityScope
    root_key_id: str
    root_public_key: Ed25519PublicKey


@dataclass(frozen=True)
class _Session:
    gate_open: bool
    recovery_generation: int


def preview_or_stage(
    context: RunnerContext,
    release_jws: bytes,
    *,
    now: datetime,
    confirm_jws_sha256: str | None,
) -> dict[str, object]:
    """Verify one release now; stage it only with its exact digest confirmed."""

    with _connect(context) as connection:
        _require_session(connection, context)
        verified = _verify_now(connection, context, release_jws, now=now)
    report = _describe(verified, status="verified_not_written")
    if confirm_jws_sha256 is None:
        return report
    if confirm_jws_sha256 != verified.jws_sha256:
        raise ReleaseRunnerRejected("release_runner_confirmation_differs")
    PostgresSignedAuthorityStore(context.database_url).stage_release(
        verified, _signing_key_id(release_jws)
    )
    with _connect(context) as connection:
        staged = _staged_digest(connection, context, verified)
    if staged != verified.jws_sha256:
        raise ReleaseRunnerRejected("release_runner_readback_differs")
    report["status"] = "staged_and_read_back"
    return report


def preview_or_activate(
    context: RunnerContext,
    release_jws: bytes,
    *,
    now: datetime,
    confirm_jws_sha256: str | None,
) -> dict[str, object]:
    """Verify the staged release against current authority now; activate only when confirmed."""

    with _connect(context) as connection:
        session = _require_session(connection, context)
        if not session.gate_open:
            raise ReleaseRunnerRejected("recovery_gate_blocked")
        verified = _verify_now(connection, context, release_jws, now=now)
        item = verified.payload
        if _staged_digest(connection, context, verified) != verified.jws_sha256:
            raise ReleaseRunnerRejected("release_runner_not_staged_as_supplied")
        head = connection.execute(
            """
            SELECT active_release_id, active_sequence FROM tiamat.release_heads
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s
            """,
            (*_scope_values(context.scope), item.release_type, item.subject_id),
        ).fetchone()
        if head is None:
            succeeds = item.predecessor_release_id is None
        else:
            succeeds = item.predecessor_release_id == head[0] and item.sequence > int(head[1])
        if not succeeds:
            raise ReleaseRunnerRejected("release_runner_not_successor")
        if item.release_type == "spending_grant":
            # Profile and policy first, then the grant (Proof 2 decision D4).
            present = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT DISTINCT release_type FROM tiamat.release_heads
                    WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
                      AND head_state = 'active'
                    """,
                    _scope_values(context.scope),
                ).fetchall()
            }
            if not {"execution_profile", "privacy_policy"} <= present:
                raise ReleaseRunnerRejected("release_runner_grant_before_profile_and_policy")
    report = _describe(verified, status="verified_not_activated")
    if confirm_jws_sha256 is None:
        return report
    if confirm_jws_sha256 != verified.jws_sha256:
        raise ReleaseRunnerRejected("release_runner_confirmation_differs")
    PostgresSignedAuthorityStore(context.database_url).activate_release(
        context.scope, item.release_type, item.subject_id, item.release_id
    )
    with _connect(context) as connection:
        row = connection.execute(
            """
            SELECT h.active_release_id, h.active_jws_sha256, h.head_state, r.state
            FROM tiamat.release_heads h
            JOIN tiamat.signed_releases r
              ON r.environment = h.environment AND r.issuer = h.issuer
             AND r.caller_id = h.caller_id AND r.realm = h.realm
             AND r.release_type = h.release_type AND r.subject_id = h.subject_id
             AND r.release_id = h.active_release_id
            WHERE h.environment = %s AND h.issuer = %s AND h.caller_id = %s AND h.realm = %s
              AND h.release_type = %s AND h.subject_id = %s
            """,
            (*_scope_values(context.scope), item.release_type, item.subject_id),
        ).fetchone()
    if row is None or tuple(row) != (item.release_id, verified.jws_sha256, "active", "active"):
        raise ReleaseRunnerRejected("release_runner_readback_differs")
    report["status"] = "activated_and_read_back"
    return report


def _connect(context: RunnerContext) -> psycopg.Connection[Any]:
    connection = psycopg.connect(context.database_url, autocommit=True)
    for name, value in (
        ("tiamat.environment", context.scope.environment),
        ("tiamat.caller_id", context.scope.caller_id),
        ("tiamat.realm", context.scope.realm),
    ):
        connection.execute("SELECT set_config(%s, %s, false)", (name, value))
    return connection


def _require_session(connection: psycopg.Connection[Any], context: RunnerContext) -> _Session:
    row = connection.execute(
        """
        SELECT current_user::text,
               (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid())
        """
    ).fetchone()
    if row is None or row[0] != RELEASE_MANAGER:
        raise ReleaseRunnerRejected("release_runner_login_is_not_the_release_manager")
    if row[1] is not True:
        raise ReleaseRunnerRejected("release_runner_requires_tls")
    identity = connection.execute(
        "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
    ).fetchone()
    if identity is None or UUID(str(identity[0])) != context.expected_ledger_id:
        raise ReleaseRunnerRejected("release_runner_ledger_differs")
    gate = connection.execute(
        "SELECT dispatch_blocked, recovery_generation FROM tiamat.restore_gate "
        "WHERE environment = %s",
        (context.scope.environment,),
    ).fetchone()
    if gate is None:
        raise ReleaseRunnerRejected("release_runner_gate_not_initialized")
    return _Session(gate_open=not bool(gate[0]), recovery_generation=int(gate[1]))


def _verify_now(
    connection: psycopg.Connection[Any],
    context: RunnerContext,
    release_jws: bytes,
    *,
    now: datetime,
) -> VerifiedRelease:
    """The current active inventory, verified against the pin, then the release under it."""

    rows = connection.execute(
        """
        SELECT exact_jws FROM tiamat.trust_inventories
        WHERE environment = %s AND state = 'active'
        """,
        (context.scope.environment,),
    ).fetchall()
    if len(rows) != 1:
        raise ReleaseRunnerRejected("release_runner_active_inventory_unavailable")
    try:
        inventory: TrustInventory = verify_trust_inventory(
            bytes(rows[0][0]),
            root_key_id=context.root_key_id,
            root_public_key=context.root_public_key,
            environment=context.scope.environment,
        )
        return verify_release(
            release_jws,
            inventory=inventory,
            expected_issuer=context.scope.issuer,
            expected_environment=context.scope.environment,
            expected_caller_id=context.scope.caller_id,
            expected_realm=context.scope.realm,
            now=now,
        )
    except SignedReleaseRejected as exc:
        raise ReleaseRunnerRejected(f"release_runner_{exc}") from exc


def _staged_digest(
    connection: psycopg.Connection[Any], context: RunnerContext, verified: VerifiedRelease
) -> str | None:
    item = verified.payload
    row = connection.execute(
        """
        SELECT jws_sha256 FROM tiamat.signed_releases
        WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
          AND release_type = %s AND subject_id = %s AND release_id = %s
        """,
        (*_scope_values(context.scope), item.release_type, item.subject_id, item.release_id),
    ).fetchone()
    return None if row is None else str(row[0])


def _signing_key_id(release_jws: bytes) -> str:
    segment = release_jws.split(b".")[0]
    header = json.loads(base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4)))
    return str(header["kid"])


def _describe(verified: VerifiedRelease, *, status: str) -> dict[str, object]:
    item = verified.payload
    return {
        "release_type": item.release_type,
        "subject_id": item.subject_id,
        "release_id": item.release_id,
        "sequence": item.sequence,
        "predecessor_release_id": item.predecessor_release_id,
        "jws_sha256": verified.jws_sha256,
        "status": status,
    }


def _scope_values(scope: AuthorityScope) -> tuple[str, str, str, str]:
    return scope.environment, scope.issuer, scope.caller_id, scope.realm
