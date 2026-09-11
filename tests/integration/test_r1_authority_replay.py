from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from lucy.authority_recovery import (
    AuthorityJournalWriter,
    AuthorityTransitionRequestV1,
    AuthorityTransitionService,
    PostgresAuthorityReplayStore,
)
from lucy.db import create_session_factory
from lucy.publication import PublicProjectionPublisher
from lucy.recovery_journal import (
    InMemoryRecoveryJournal,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
TRANSITION_URL = os.getenv("LUCY_TEST_AUTHORITY_DATABASE_URL")
RECOVERY_URL = os.getenv("LUCY_TEST_AUTHORITY_RECOVERY_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not all((APP_URL, OWNER_URL, TRANSITION_URL, RECOVERY_URL)),
    reason="requires PostgreSQL authority-replay integration database",
)


@pytest.fixture(autouse=True)
def clean_authority_replay_tables() -> None:
    assert OWNER_URL is not None
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        if connection.scalar(text("SELECT current_database()")) != "lucy_test":
            raise RuntimeError("refusing to clear a non-synthetic database")
        connection.execute(
            text(
                "TRUNCATE lucy.restored_recovery_events_v1,"
                "lucy.restored_recovery_heads_v1,lucy.authority_recovery_outbox_v1,"
                "lucy.authority_transition_events_v1,lucy.public_projection_events,"
                "lucy.public_projection_routes,lucy.public_projection_versions,"
                "lucy.public_projection_approvals,lucy.public_projection_candidates,"
                "lucy.scoped_capture_receipts_v1,lucy.scoped_capture_states_v1,"
                "lucy.lucy_instances,lucy.node_memberships,lucy.channel_bindings,"
                "lucy.wallet_registrations,lucy.workspaces,lucy.realm_bindings,"
                "lucy.node_tenures,lucy.security_realms,lucy.nodes,"
                "lucy.tenant_accounts,lucy.principals CASCADE"
            )
        )
        connection.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='quarantined',"
                "storage_epoch=NULL,updated_at=now() WHERE singleton"
            )
        )
    engine.dispose()


def _binding() -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=RecoveryStreamKind.AUTHORITY,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id="dynamodb:synthetic-authority",
        writer_identity="synthetic-authority-writer",
        recovery_identity="synthetic-authority-recovery",
        binding_manifest_digest="a" * 64,
    )


def test_quarantined_restore_replays_exact_authority_suffix_once() -> None:
    assert APP_URL is not None and OWNER_URL is not None
    assert TRANSITION_URL is not None and RECOVERY_URL is not None
    tenancy = TenancyService(create_session_factory(APP_URL))
    foundation = tenancy.create_node_foundation(
        account_slug="utopia",
        account_name="Utopia",
        node_slug="utopia",
        node_name="Utopia Homes",
        node_kind="organization",
        realm_slug="utopia-realm",
        workspace_slug="website",
        hostname="utopia.test",
    )
    owner = tenancy.create_principal(
        issuer="synthetic", subject="owner", kind="human", display_name="Owner"
    )
    member = tenancy.create_principal(
        issuer="synthetic", subject="member", kind="human", display_name="Member"
    )
    tenancy.grant_workspace_membership(
        principal_id=owner, workspace_id=foundation.workspace_id, role="owner"
    )
    membership_id = tenancy.grant_workspace_membership(
        principal_id=member, workspace_id=foundation.workspace_id, role="publisher"
    )
    publisher = PublicProjectionPublisher(create_session_factory(APP_URL))
    candidate_id, candidate_digest = publisher.stage(
        channel_binding_id=foundation.channel_binding_id,
        entries=[{"question": "hello", "answer": "Hi", "source": "synthetic"}],
        actor_id=member,
    )
    publisher.approve(
        candidate_id=candidate_id, expected_digest=candidate_digest, actor_id=owner
    )
    published_version_id = publisher.publish(candidate_id=candidate_id, actor_id=member)

    binding = _binding()
    transition = AuthorityTransitionService(create_session_factory(TRANSITION_URL))
    staged = transition.revoke_membership(
        AuthorityTransitionRequestV1(
            subject_id=membership_id,
            actor_id=owner,
            stream_id=binding.stream_id,
            authority_epoch=binding.authority_epoch,
            idempotency_key="authority:restore:membership-1",
            source_authority_ref="owner-interaction:synthetic",
            source_authority_digest="b" * 64,
        )
    )
    journal = InMemoryRecoveryJournal(binding)
    writer = AuthorityJournalWriter(transition, journal)
    membership_acknowledgement = writer.append_pending(staged.event_id)
    withdrawal = transition.withdraw_publication(
        AuthorityTransitionRequestV1(
            subject_id=foundation.channel_binding_id,
            actor_id=owner,
            stream_id=binding.stream_id,
            authority_epoch=binding.authority_epoch,
            idempotency_key="authority:restore:publication-1",
            source_authority_ref="owner-interaction:synthetic",
            source_authority_digest="c" * 64,
        )
    )
    publication_acknowledgement = writer.append_pending(withdrawal.event_id)
    membership_event = journal.event(1)
    publication_event = journal.event(2)

    # Model a backup that predates the restriction while keeping the independent event.
    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE lucy.node_memberships DISABLE TRIGGER "
                "membership_authority_monotonic"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE lucy.node_memberships DISABLE TRIGGER "
                "node_membership_authority_restriction_guard_v1"
            )
        )
        connection.execute(
            text(
                "UPDATE lucy.node_memberships SET status='active',generation=:generation "
                "WHERE id=:membership"
            ),
            {"membership": membership_id, "generation": staged.previous_generation},
        )
        connection.execute(
            text(
                "ALTER TABLE lucy.node_memberships ENABLE TRIGGER "
                "membership_authority_monotonic"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE lucy.node_memberships ENABLE TRIGGER "
                "node_membership_authority_restriction_guard_v1"
            )
        )
        connection.execute(
            text(
                "UPDATE lucy.public_projection_routes SET active_version_id=:version,"
                "authority_generation=:generation WHERE channel_binding_id=:channel"
            ),
            {
                "version": published_version_id,
                "generation": withdrawal.previous_generation,
                "channel": foundation.channel_binding_id,
            },
        )

    restored = PostgresAuthorityReplayStore(
        create_session_factory(RECOVERY_URL), binding
    )
    genesis = restored.head()
    assert genesis.sequence == 0
    membership_head = restored.apply(membership_event, genesis)
    assert membership_head == membership_acknowledgement.resulting_head
    final_head = restored.apply(publication_event, membership_head)
    assert final_head == publication_acknowledgement.resulting_head
    assert restored.head() == publication_acknowledgement.resulting_head
    assert restored.apply(membership_event, genesis) == membership_head

    with create_engine(OWNER_URL).connect() as connection:
        state = connection.execute(
            text("SELECT status,generation FROM lucy.node_memberships WHERE id=:membership"),
            {"membership": membership_id},
        ).one()
        assert state == ("revoked", staged.new_generation)
        route = connection.execute(
            text(
                "SELECT active_version_id,authority_generation "
                "FROM lucy.public_projection_routes WHERE channel_binding_id=:channel"
            ),
            {"channel": foundation.channel_binding_id},
        ).one()
        assert route == (None, withdrawal.new_generation)
        assert connection.scalar(
            text("SELECT count(*) FROM lucy.restored_recovery_events_v1")
        ) == 2


def test_replay_login_is_execute_only_and_fail_closed() -> None:
    assert APP_URL is not None and TRANSITION_URL is not None and RECOVERY_URL is not None
    binding = _binding()
    restored = PostgresAuthorityReplayStore(create_session_factory(RECOVERY_URL), binding)

    with create_engine(APP_URL).connect() as connection, pytest.raises(
        DBAPIError, match="permission denied"
    ):
        connection.execute(text("SELECT lucy.restored_recovery_head_v1('authority')"))
    with create_engine(TRANSITION_URL).connect() as connection, pytest.raises(
        DBAPIError, match="permission denied"
    ):
        connection.execute(text("SELECT lucy.restored_recovery_head_v1('authority')"))
    with create_engine(RECOVERY_URL).connect() as connection, pytest.raises(
        DBAPIError, match="permission denied"
    ):
        connection.execute(text("SELECT * FROM lucy.restored_recovery_events_v1"))

    with pytest.raises(ValueError, match="authority binding"):
        PostgresAuthorityReplayStore(
            create_session_factory(RECOVERY_URL),
            binding.model_copy(update={"stream_kind": RecoveryStreamKind.COST}),
        )

    with create_engine(RECOVERY_URL).begin() as connection, pytest.raises(
        DBAPIError, match="authority recovery event is invalid"
    ):
        connection.execute(
            text(
                "SELECT lucy.apply_authority_recovery_event_v1("
                "CAST(:expected AS jsonb),CAST(:event AS jsonb))"
            ),
            {
                "expected": json.dumps(restored.head().model_dump(mode="json")),
                "event": json.dumps({"contract_version": "1", "stream_kind": "authority"}),
            },
        )


def test_quarantined_restore_replays_private_channel_activation_then_withdrawal() -> None:
    assert APP_URL is not None and OWNER_URL is not None
    assert TRANSITION_URL is not None and RECOVERY_URL is not None
    tenancy = TenancyService(create_session_factory(APP_URL))
    foundation = tenancy.create_node_foundation(
        account_slug="telegram-replay",
        account_name="Telegram Replay",
        node_slug=f"telegram-replay-{uuid4()}",
        node_name="Telegram Replay",
        node_kind="organization",
        realm_slug=f"telegram-replay-realm-{uuid4()}",
        workspace_slug="private-lucy",
        hostname=f"telegram-replay-{uuid4()}.invalid",
        workspace_kind="private_lucy",
        channel_kind="internal",
    )
    owner_id = tenancy.create_principal(
        issuer="synthetic",
        subject=f"telegram-replay-owner-{uuid4()}",
        kind="human",
        display_name="Telegram Replay Owner",
    )
    tenancy.grant_workspace_membership(
        principal_id=owner_id, workspace_id=foundation.workspace_id, role="owner"
    )
    binding_digest = "9" * 64
    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(
                "UPDATE lucy.channel_bindings SET active=false,generation=generation+1 "
                "WHERE id=:channel"
            ),
            {"channel": foundation.channel_binding_id},
        )
        connection.execute(
            text(
                "INSERT INTO lucy.telegram_channel_bindings_v1("
                "channel_binding_id,bot_id,owner_user_id,binding_digest,created_at) "
                "VALUES (:channel,910000001,910000002,:digest,:created_at)"
            ),
            {
                "channel": foundation.channel_binding_id,
                "digest": binding_digest,
                "created_at": datetime.now(UTC),
            },
        )

    stream = _binding()
    transition = AuthorityTransitionService(create_session_factory(TRANSITION_URL))
    acknowledgement = AuthorityTransitionService(create_session_factory(RECOVERY_URL))
    journal = InMemoryRecoveryJournal(stream)
    writer = AuthorityJournalWriter(transition, journal)
    base_request = AuthorityTransitionRequestV1(
        subject_id=foundation.channel_binding_id,
        actor_id=owner_id,
        stream_id=stream.stream_id,
        authority_epoch=stream.authority_epoch,
        idempotency_key="authority:restore:telegram-activate-1",
        source_authority_ref="owner-interaction:synthetic",
        source_authority_digest=binding_digest,
    )
    activation = transition.activate_channel(base_request)
    activation_append = writer.append_pending(activation.event_id)
    acknowledgement.acknowledge(
        event_id=activation.event_id,
        journal_sequence=activation_append.resulting_head.sequence,
        journal_event_digest=activation_append.event_digest,
        journal_head_digest=activation_append.event_digest,
    )
    withdrawal = transition.withdraw_channel(
        base_request.model_copy(
            update={"idempotency_key": "authority:restore:telegram-withdraw-1"}
        )
    )
    withdrawal_append = writer.append_pending(withdrawal.event_id)
    acknowledgement.acknowledge(
        event_id=withdrawal.event_id,
        journal_sequence=withdrawal_append.resulting_head.sequence,
        journal_event_digest=withdrawal_append.event_digest,
        journal_head_digest=withdrawal_append.event_digest,
    )

    # Model a backup from before either transition; recovery must end withdrawn.
    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE lucy.channel_bindings DISABLE TRIGGER "
                "channel_authority_monotonic"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE lucy.channel_bindings DISABLE TRIGGER "
                "channel_binding_authority_guard_v1"
            )
        )
        connection.execute(
            text(
                "UPDATE lucy.channel_bindings SET active=false,generation=:generation "
                "WHERE id=:channel"
            ),
            {
                "channel": foundation.channel_binding_id,
                "generation": activation.previous_generation,
            },
        )
        connection.execute(
            text(
                "ALTER TABLE lucy.channel_bindings ENABLE TRIGGER "
                "channel_authority_monotonic"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE lucy.channel_bindings ENABLE TRIGGER "
                "channel_binding_authority_guard_v1"
            )
        )
    restored = PostgresAuthorityReplayStore(
        create_session_factory(RECOVERY_URL), stream
    )
    activation_head = restored.apply(journal.event(1), restored.head())
    assert activation_head == activation_append.resulting_head
    final_head = restored.apply(journal.event(2), activation_head)
    assert final_head == withdrawal_append.resulting_head
    with create_engine(OWNER_URL).connect() as connection:
        state = connection.execute(
            text(
                "SELECT active,generation FROM lucy.channel_bindings WHERE id=:channel"
            ),
            {"channel": foundation.channel_binding_id},
        ).one()
        assert state == (False, withdrawal.new_generation)
