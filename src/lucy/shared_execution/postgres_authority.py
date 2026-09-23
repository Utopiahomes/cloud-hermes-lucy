"""Transactional PostgreSQL storage for verified Tiamat signed authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.rows import dict_row

from lucy.shared_execution.authority_fence import authority_subject_lock
from lucy.shared_execution.postgres_ledger import _psycopg_conninfo
from lucy.shared_execution.signed_releases import (
    RevocationRelease,
    SpendingGrantRelease,
    TrustInventory,
    VerifiedRelease,
)


class AuthorityStoreUnavailable(RuntimeError):
    """The authoritative release store could not establish current state."""


class AuthorityTransitionRejected(RuntimeError):
    """A staging or activation transition violated monotonic authority."""


@dataclass(frozen=True)
class AuthorityScope:
    environment: str
    issuer: str
    caller_id: str
    realm: str


class PostgresSignedAuthorityStore:
    """Persist exact verified JWS objects and atomically advance scoped heads."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def stage_inventory(self, exact_jws: bytes, inventory: TrustInventory, jws_sha256: str) -> None:
        try:
            with self._connect() as connection, connection.transaction():
                self._set_environment(connection, inventory.environment)
                row = connection.execute(
                    """
                    INSERT INTO tiamat.trust_inventories (
                        environment, inventory_generation, exact_jws, jws_sha256,
                        previous_inventory_digest, root_key_id, state
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'staged')
                    ON CONFLICT (environment, inventory_generation) DO NOTHING
                    RETURNING jws_sha256
                    """,
                    (
                        inventory.environment,
                        inventory.inventory_generation,
                        exact_jws,
                        jws_sha256,
                        inventory.previous_inventory_digest,
                        inventory.root_key_id,
                    ),
                ).fetchone()
                if row is None:
                    existing = connection.execute(
                        """
                        SELECT jws_sha256 FROM tiamat.trust_inventories
                        WHERE environment = %s AND inventory_generation = %s
                        """,
                        (inventory.environment, inventory.inventory_generation),
                    ).fetchone()
                    if existing is None or existing["jws_sha256"] != jws_sha256:
                        raise AuthorityTransitionRejected("inventory_generation_conflict")
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def activate_inventory(self, environment: str, inventory_generation: int) -> None:
        try:
            with self._connect() as connection, connection.transaction():
                self._set_environment(connection, environment)
                recovery_generation = self._assert_recovery_gate_open(connection, environment)
                current = connection.execute(
                    """
                    SELECT inventory_generation, jws_sha256
                    FROM tiamat.trust_inventories
                    WHERE environment = %s AND state = 'active'
                    FOR UPDATE
                    """,
                    (environment,),
                ).fetchone()
                candidate = connection.execute(
                    """
                    SELECT inventory_generation, previous_inventory_digest, state
                    FROM tiamat.trust_inventories
                    WHERE environment = %s AND inventory_generation = %s
                    FOR UPDATE
                    """,
                    (environment, inventory_generation),
                ).fetchone()
                if candidate is None or candidate["state"] != "staged":
                    raise AuthorityTransitionRejected("inventory_not_staged")
                if current is None:
                    valid = (
                        candidate["inventory_generation"] == 1
                        and candidate["previous_inventory_digest"] is None
                    )
                else:
                    valid = (
                        candidate["inventory_generation"] > current["inventory_generation"]
                        and candidate["previous_inventory_digest"] == current["jws_sha256"]
                    )
                if not valid:
                    raise AuthorityTransitionRejected("inventory_not_successor")
                connection.execute(
                    """
                    UPDATE tiamat.trust_inventories SET state = 'superseded'
                    WHERE environment = %s AND state = 'active'
                    """,
                    (environment,),
                )
                connection.execute(
                    """
                    UPDATE tiamat.trust_inventories
                    SET state = 'active', activated_at = clock_timestamp(),
                        activation_recovery_generation = %s
                    WHERE environment = %s AND inventory_generation = %s
                    """,
                    (recovery_generation, environment, inventory_generation),
                )
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def stage_release(self, release: VerifiedRelease, signing_key_id: str) -> None:
        item = release.payload
        try:
            with self._connect() as connection, connection.transaction():
                scope = AuthorityScope(item.environment, item.issuer, item.caller_id, item.realm)
                self._set_scope(connection, scope)
                row = connection.execute(
                    """
                    INSERT INTO tiamat.signed_releases (
                        environment, issuer, caller_id, realm, release_type, subject_id,
                        release_id, sequence, predecessor_release_id, signing_key_id,
                        not_before, not_after, content_digest, exact_jws, jws_sha256, state
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::timestamptz, %s::timestamptz, %s, %s, %s, 'staged'
                    )
                    ON CONFLICT (
                        environment, issuer, caller_id, realm, release_type, subject_id, release_id
                    ) DO NOTHING
                    RETURNING jws_sha256
                    """,
                    (
                        item.environment,
                        item.issuer,
                        item.caller_id,
                        item.realm,
                        item.release_type,
                        item.subject_id,
                        item.release_id,
                        item.sequence,
                        item.predecessor_release_id,
                        signing_key_id,
                        item.not_before,
                        item.not_after,
                        item.content_digest,
                        release.exact_jws,
                        release.jws_sha256,
                    ),
                ).fetchone()
                if row is None:
                    existing = connection.execute(
                        """
                        SELECT jws_sha256 FROM tiamat.signed_releases
                        WHERE environment = %s AND issuer = %s AND caller_id = %s
                          AND realm = %s AND release_type = %s AND subject_id = %s
                          AND release_id = %s
                        """,
                        (
                            item.environment,
                            item.issuer,
                            item.caller_id,
                            item.realm,
                            item.release_type,
                            item.subject_id,
                            item.release_id,
                        ),
                    ).fetchone()
                    if existing is None or existing["jws_sha256"] != release.jws_sha256:
                        raise AuthorityTransitionRejected("release_id_conflict")
                if isinstance(item, SpendingGrantRelease):
                    grant = item.content
                    # Grant rows are scoped by partition under row-level security.
                    connection.execute(
                        "SELECT set_config('tiamat.partition_id', %s, true)",
                        (grant.partition_id,),
                    )
                    connection.execute(
                        """
                        INSERT INTO tiamat.grant_releases (
                            release_id, environment, caller_id, realm, partition_id,
                            budget_period_id, predecessor_release_id, not_before, not_after,
                            period_start, period_end, allowance_microusd, maximum_concurrency,
                            largest_per_call_microusd, contingency_reserve_microusd,
                            signed_artifact_digest
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s::timestamptz, %s::timestamptz,
                            %s::timestamptz, %s::timestamptz, %s, %s, %s, %s, %s
                        ) ON CONFLICT (release_id) DO NOTHING
                        """,
                        (
                            item.release_id,
                            item.environment,
                            item.caller_id,
                            item.realm,
                            grant.partition_id,
                            grant.budget_period_id,
                            item.predecessor_release_id,
                            item.not_before,
                            item.not_after,
                            grant.period_start,
                            grant.period_end,
                            grant.allowance_microusd,
                            grant.maximum_concurrency,
                            grant.largest_per_call_microusd,
                            grant.contingency_reserve_microusd,
                            release.jws_sha256,
                        ),
                    )
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def activate_release(
        self, scope: AuthorityScope, release_type: str, subject_id: str, release_id: str
    ) -> None:
        """Activate a staged successor under the subject's exclusive authority lock.

        A revocation release is not activated here: its activation and its effect must be one
        commit, which ``activate_revocation`` provides.
        """

        if release_type == "revocation":
            raise AuthorityTransitionRejected("revocation_requires_activate_revocation")
        try:
            with self._connect() as connection, connection.transaction():
                self._set_scope(connection, scope)
                recovery_generation = self._assert_recovery_gate_open(connection, scope.environment)
                _lock_subjects(connection, scope, {(release_type, subject_id)})
                self._activate(
                    connection, scope, recovery_generation, release_type, subject_id, release_id
                )
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def activate_revocation(self, scope: AuthorityScope, revocation: VerifiedRelease) -> None:
        """Activate a staged revocation release and apply it in the same commit.

        RC1 orders a revocation by when it is activated. Activating it in one transaction and
        applying it in another would leave a window in which it is active but not yet enforced,
        so a completed commit could deliver under it. Both subjects' locks are taken first, in a
        fixed order, before any row is locked.
        """

        item = revocation.payload
        if not isinstance(item, RevocationRelease):
            raise AuthorityTransitionRejected("release_is_not_revocation")
        try:
            with self._connect() as connection, connection.transaction():
                self._set_scope(connection, scope)
                recovery_generation = self._assert_recovery_gate_open(connection, scope.environment)
                target_subject = self._revocation_target_subject(connection, scope, item)
                _lock_subjects(
                    connection,
                    scope,
                    {
                        ("revocation", item.subject_id),
                        (item.content.target_release_type, target_subject),
                    },
                )
                self._activate(
                    connection,
                    scope,
                    recovery_generation,
                    "revocation",
                    item.subject_id,
                    item.release_id,
                )
                self._apply(connection, scope, item, target_subject)
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def _activate(
        self,
        connection: psycopg.Connection[dict[str, Any]],
        scope: AuthorityScope,
        recovery_generation: int,
        release_type: str,
        subject_id: str,
        release_id: str,
    ) -> None:
        """The activation statements. The caller holds the transaction and the subject lock."""

        candidate = connection.execute(
            """
            SELECT release_id, sequence, predecessor_release_id, jws_sha256, state
            FROM tiamat.signed_releases
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s AND release_id = %s
            FOR UPDATE
            """,
            (*self._scope_values(scope), release_type, subject_id, release_id),
        ).fetchone()
        head = connection.execute(
            """
            SELECT active_release_id, active_sequence, eligibility_generation
            FROM tiamat.release_heads
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s
            FOR UPDATE
            """,
            (*self._scope_values(scope), release_type, subject_id),
        ).fetchone()
        if candidate is None or candidate["state"] != "staged":
            raise AuthorityTransitionRejected("release_not_staged")
        if head is None:
            valid = candidate["predecessor_release_id"] is None
            generation = 1
        else:
            valid = (
                candidate["sequence"] > head["active_sequence"]
                and candidate["predecessor_release_id"] == head["active_release_id"]
            )
            generation = head["eligibility_generation"] + 1
        if not valid:
            raise AuthorityTransitionRejected("release_not_successor")
        connection.execute(
            """
            UPDATE tiamat.signed_releases SET state = 'superseded'
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s AND state = 'active'
            """,
            (*self._scope_values(scope), release_type, subject_id),
        )
        connection.execute(
            """
            UPDATE tiamat.signed_releases
            SET state = 'active', activated_at = clock_timestamp()
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s AND release_id = %s
            """,
            (*self._scope_values(scope), release_type, subject_id, release_id),
        )
        connection.execute(
            """
            INSERT INTO tiamat.release_heads (
                environment, issuer, caller_id, realm, release_type, subject_id,
                active_release_id, active_jws_sha256, active_sequence,
                recovery_generation, eligibility_generation
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (environment, issuer, caller_id, realm, release_type, subject_id)
            DO UPDATE SET active_release_id = EXCLUDED.active_release_id,
              active_jws_sha256 = EXCLUDED.active_jws_sha256,
              active_sequence = EXCLUDED.active_sequence,
              head_state = 'active', revocation_release_id = NULL,
              recovery_generation = EXCLUDED.recovery_generation,
              eligibility_generation = EXCLUDED.eligibility_generation,
              updated_at = clock_timestamp()
            """,
            (
                *self._scope_values(scope),
                release_type,
                subject_id,
                candidate["release_id"],
                candidate["jws_sha256"],
                candidate["sequence"],
                recovery_generation,
                generation,
            ),
        )
        if release_type == "spending_grant":
            # A grant's subject is its partition, which scopes both rows it projects between.
            connection.execute(
                "SELECT set_config('tiamat.partition_id', %s, true)", (subject_id,)
            )
            projected = connection.execute(
                """
                UPDATE tiamat.spending_partitions p
                SET active_grant_release_id = g.release_id,
                    budget_period_id = g.budget_period_id,
                    allowance_microusd = g.allowance_microusd,
                    contingency_reserve_microusd = g.contingency_reserve_microusd,
                    maximum_concurrency = g.maximum_concurrency,
                    largest_per_call_microusd = g.largest_per_call_microusd,
                    -- A grant answers only the absence of a grant. Any other block,
                    -- such as an unfunded settlement liability, outlives the activation.
                    blocked = p.blocked AND p.block_reason IS DISTINCT FROM 'no_active_grant',
                    block_reason = CASE
                        WHEN p.blocked AND p.block_reason IS DISTINCT FROM 'no_active_grant'
                        THEN p.block_reason
                    END,
                    generation = p.generation + 1,
                    updated_at = clock_timestamp()
                FROM tiamat.grant_releases g
                WHERE g.release_id = %s
                  AND p.environment = g.environment AND p.caller_id = g.caller_id
                  AND p.realm = g.realm AND p.partition_id = g.partition_id
                RETURNING p.partition_id
                """,
                (release_id,),
            ).fetchone()
            if projected is None:
                raise AuthorityTransitionRejected("spending_partition_unavailable")
            connection.execute(
                """
                UPDATE tiamat.grant_releases SET activated_at = clock_timestamp()
                WHERE release_id = %s
                """,
                (release_id,),
            )

    def load_active_jws(self, scope: AuthorityScope, release_type: str, subject_id: str) -> bytes:
        try:
            with self._connect() as connection, connection.transaction():
                self._set_scope(connection, scope)
                recovery_generation = self._assert_recovery_gate_open(connection, scope.environment)
                row = connection.execute(
                    """
                    SELECT r.exact_jws
                    FROM tiamat.release_heads h
                    JOIN tiamat.restore_gate gate ON gate.environment = h.environment
                    JOIN tiamat.signed_releases r
                      ON r.environment = h.environment AND r.issuer = h.issuer
                     AND r.caller_id = h.caller_id AND r.realm = h.realm
                     AND r.release_type = h.release_type AND r.subject_id = h.subject_id
                     AND r.release_id = h.active_release_id
                     AND r.jws_sha256 = h.active_jws_sha256
                    WHERE h.environment = %s AND h.issuer = %s AND h.caller_id = %s
                      AND h.realm = %s AND h.release_type = %s AND h.subject_id = %s
                      AND h.head_state = 'active' AND r.state = 'active'
                      AND h.recovery_generation = gate.recovery_generation
                    """,
                    (*self._scope_values(scope), release_type, subject_id),
                ).fetchone()
                if row is None:
                    raise AuthorityTransitionRejected("active_release_unavailable")
                if recovery_generation < 1:
                    raise AuthorityTransitionRejected("recovery_gate_blocked")
                return bytes(row["exact_jws"])
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def load_active_inventory_jws(self, environment: str) -> bytes:
        try:
            with self._connect() as connection, connection.transaction():
                self._set_environment(connection, environment)
                generation = self._assert_recovery_gate_open(connection, environment)
                row = connection.execute(
                    """
                    SELECT exact_jws FROM tiamat.trust_inventories
                    WHERE environment = %s AND state = 'active'
                      AND activation_recovery_generation = %s
                    """,
                    (environment, generation),
                ).fetchone()
                if row is None:
                    raise AuthorityTransitionRejected("active_inventory_unavailable")
                return bytes(row["exact_jws"])
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def load_active_jws_by_release_id(
        self, scope: AuthorityScope, release_type: str, release_id: str
    ) -> bytes:
        try:
            with self._connect() as connection, connection.transaction():
                self._set_scope(connection, scope)
                generation = self._assert_recovery_gate_open(connection, scope.environment)
                rows = connection.execute(
                    """
                    SELECT r.exact_jws
                    FROM tiamat.release_heads h
                    JOIN tiamat.signed_releases r
                      ON r.environment = h.environment AND r.issuer = h.issuer
                     AND r.caller_id = h.caller_id AND r.realm = h.realm
                     AND r.release_type = h.release_type AND r.subject_id = h.subject_id
                     AND r.release_id = h.active_release_id
                     AND r.jws_sha256 = h.active_jws_sha256
                    WHERE h.environment = %s AND h.issuer = %s AND h.caller_id = %s
                      AND h.realm = %s AND h.release_type = %s AND h.active_release_id = %s
                      AND h.head_state = 'active' AND h.recovery_generation = %s
                      AND r.state = 'active'
                    """,
                    (*self._scope_values(scope), release_type, release_id, generation),
                ).fetchall()
                if len(rows) != 1:
                    raise AuthorityTransitionRejected("active_release_unavailable")
                return bytes(rows[0]["exact_jws"])
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def apply_revocation(self, scope: AuthorityScope, revocation: VerifiedRelease) -> None:
        """Re-apply an already active revocation; applying it again is a no-op.

        A new revocation is activated and applied together by ``activate_revocation``.
        """

        item = revocation.payload
        if not isinstance(item, RevocationRelease):
            raise AuthorityTransitionRejected("release_is_not_revocation")
        try:
            with self._connect() as connection, connection.transaction():
                self._set_scope(connection, scope)
                self._assert_recovery_gate_open(connection, scope.environment)
                target_subject = self._revocation_target_subject(connection, scope, item)
                _lock_subjects(
                    connection, scope, {(item.content.target_release_type, target_subject)}
                )
                self._apply(connection, scope, item, target_subject)
        except AuthorityTransitionRejected:
            raise
        except psycopg.Error as exc:
            raise AuthorityStoreUnavailable from exc

    def _revocation_target_subject(
        self,
        connection: psycopg.Connection[dict[str, Any]],
        scope: AuthorityScope,
        item: RevocationRelease,
    ) -> str:
        """Find the targeted subject without locking, so its lock can be taken first."""

        target = item.content
        rows = connection.execute(
            """
            SELECT subject_id
            FROM tiamat.signed_releases
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND release_id = %s
            """,
            (*self._scope_values(scope), target.target_release_type, target.target_release_id),
        ).fetchall()
        if len(rows) != 1:
            raise AuthorityTransitionRejected("revocation_target_ambiguous")
        return str(rows[0]["subject_id"])

    def _apply(
        self,
        connection: psycopg.Connection[dict[str, Any]],
        scope: AuthorityScope,
        item: RevocationRelease,
        target_subject: str,
    ) -> None:
        """The revocation statements. The caller holds the transaction and the target's lock.

        Dispatch and the completed commit take that lock shared, so whichever commits first is
        the one that counts. The subject's revocation generation increments here and nowhere
        else, so a later successor cannot hide that the subject was revoked.
        """

        target = item.content
        revocation_head = connection.execute(
            """
            SELECT active_release_id, head_state
            FROM tiamat.release_heads
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = 'revocation' AND subject_id = %s
            FOR SHARE
            """,
            (*self._scope_values(scope), item.subject_id),
        ).fetchone()
        if (
            revocation_head is None
            or revocation_head["head_state"] != "active"
            or revocation_head["active_release_id"] != item.release_id
        ):
            raise AuthorityTransitionRejected("revocation_not_active")
        target_row = connection.execute(
            """
            SELECT subject_id, release_id, state
            FROM tiamat.signed_releases
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s AND release_id = %s
            FOR UPDATE
            """,
            (
                *self._scope_values(scope),
                target.target_release_type,
                target_subject,
                target.target_release_id,
            ),
        ).fetchone()
        if target_row is None:
            raise AuthorityTransitionRejected("revocation_target_ambiguous")
        head = connection.execute(
            """
            SELECT active_release_id, head_state, revocation_release_id
            FROM tiamat.release_heads
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s
            FOR UPDATE
            """,
            (*self._scope_values(scope), target.target_release_type, target_subject),
        ).fetchone()
        if head is None or head["active_release_id"] != target.target_release_id:
            raise AuthorityTransitionRejected("revocation_target_not_head")
        if head["head_state"] == "revoked":
            if head["revocation_release_id"] == item.release_id:
                return
            raise AuthorityTransitionRejected("revocation_conflict")
        connection.execute(
            """
            UPDATE tiamat.signed_releases
            SET state = 'revoked', revoked_at = %s::timestamptz
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s AND release_id = %s
            """,
            (
                target.effective_at,
                *self._scope_values(scope),
                target.target_release_type,
                target_subject,
                target.target_release_id,
            ),
        )
        connection.execute(
            """
            UPDATE tiamat.release_heads
            SET head_state = 'revoked', revocation_release_id = %s,
                eligibility_generation = eligibility_generation + 1,
                revocation_generation = revocation_generation + 1,
                updated_at = clock_timestamp()
            WHERE environment = %s AND issuer = %s AND caller_id = %s AND realm = %s
              AND release_type = %s AND subject_id = %s
            """,
            (
                item.release_id,
                *self._scope_values(scope),
                target.target_release_type,
                target_subject,
            ),
        )

    def _connect(self) -> psycopg.Connection[dict[str, Any]]:
        return psycopg.connect(_psycopg_conninfo(self._database_url), row_factory=dict_row)

    @staticmethod
    def _set_environment(connection: psycopg.Connection[dict[str, Any]], environment: str) -> None:
        connection.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))

    @classmethod
    def _set_scope(
        cls, connection: psycopg.Connection[dict[str, Any]], scope: AuthorityScope
    ) -> None:
        cls._set_environment(connection, scope.environment)
        connection.execute("SELECT set_config('tiamat.caller_id', %s, true)", (scope.caller_id,))
        connection.execute("SELECT set_config('tiamat.realm', %s, true)", (scope.realm,))

    @staticmethod
    def _scope_values(scope: AuthorityScope) -> tuple[str, str, str, str]:
        return scope.environment, scope.issuer, scope.caller_id, scope.realm

    @staticmethod
    def _assert_recovery_gate_open(
        connection: psycopg.Connection[dict[str, Any]], environment: str
    ) -> int:
        # The release manager holds SELECT only, so it takes the gate's shared lock through the
        # same definer function the serving role uses. The scope comes from the session setting.
        connection.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        row = connection.execute(
            """
            SELECT dispatch_blocked, recovery_generation
            FROM tiamat.share_locked_restore_gate()
            """
        ).fetchone()
        if row is None or row["dispatch_blocked"]:
            raise AuthorityTransitionRejected("recovery_gate_blocked")
        return int(row["recovery_generation"])


def _lock_subjects(
    connection: psycopg.Connection[dict[str, Any]],
    scope: AuthorityScope,
    subjects: set[tuple[str, str]],
) -> None:
    """Take each subject's authority lock exclusively, in one fixed order, before any row lock.

    Activation and revocation of one subject used to lock its release rows and head in opposite
    orders and could deadlock. Taking the subject lock first serializes them outright.
    """

    for class_id, object_id in sorted(
        authority_subject_lock(scope.environment, scope.caller_id, scope.realm, kind, subject)
        for kind, subject in subjects
    ):
        connection.execute("SELECT pg_advisory_xact_lock(%s, %s)", (class_id, object_id))
