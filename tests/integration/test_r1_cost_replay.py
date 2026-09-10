from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from lucy.cost_admission import (
    ProviderAttemptRequestV1,
    ProviderCostAdmissionService,
    ProviderCostPolicyV1,
    ProviderCostRecoveryService,
)
from lucy.cost_recovery import (
    CostJournalPreparationService,
    CostJournalWriter,
    PostgresCostReplayStore,
)
from lucy.db import create_session_factory
from lucy.recovery_journal import (
    InMemoryRecoveryJournal,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
COST_URL = os.getenv("LUCY_TEST_COST_DATABASE_URL")
RECOVERY_URL = os.getenv("LUCY_TEST_COST_RECOVERY_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not all((APP_URL, OWNER_URL, COST_URL, RECOVERY_URL)),
    reason="requires PostgreSQL cost-replay integration database",
)


@pytest.fixture(autouse=True)
def clean_cost_replay_tables() -> None:
    assert OWNER_URL is not None
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        if connection.scalar(text("SELECT current_database()")) != "lucy_test":
            raise RuntimeError("refusing to clear a non-synthetic database")
        connection.execute(
            text(
                "TRUNCATE lucy.restored_cost_exposures_v1,"
                "lucy.restored_cost_admission_v1,lucy.restored_recovery_events_v1,"
                "lucy.restored_recovery_heads_v1,lucy.cost_journal_preparations_v1,"
                "lucy.cost_events_v1,lucy.cost_recovery_outbox_v1,"
                "lucy.exposure_reservations_v1,lucy.provider_attempts_v1,"
                "lucy.provider_cost_policies_v1,lucy.public_projection_events,"
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
        stream_kind=RecoveryStreamKind.COST,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id="dynamodb:synthetic-cost",
        writer_identity="synthetic-cost-writer",
        recovery_identity="synthetic-cost-recovery",
        binding_manifest_digest="d" * 64,
    )


def _foundation_policy_attempt():
    assert APP_URL is not None and OWNER_URL is not None
    foundation = TenancyService(create_session_factory(APP_URL)).create_node_foundation(
        account_slug="utopia",
        account_name="Utopia",
        node_slug="utopia",
        node_name="Utopia Homes",
        node_kind="organization",
        realm_slug="utopia-realm",
        workspace_slug="website",
        hostname="utopia.test",
    )
    policy = ProviderCostPolicyV1(
        policy_id=uuid4(),
        version=1,
        node_id=foundation.node_id,
        channel_binding_id=foundation.channel_binding_id,
        provider="openrouter",
        model="openai/gpt-oss-20b",
        rate_version="synthetic-v1",
        effective_at=datetime.now(UTC),
        kill_state="enabled",
        platform_daily_cap_microusd=20_000,
        node_daily_cap_microusd=20_000,
        site_daily_cap_microusd=20_000,
        provider_daily_cap_microusd=20_000,
        outstanding_cap_microusd=10_000,
        concurrency_limit=2,
        requests_per_minute=20,
        session_requests_per_minute=20,
        ip_requests_per_minute=20,
        per_request_cap_microusd=10_000,
        max_input_tokens=1_000,
        max_output_tokens=500,
        max_request_bytes=8_000,
        timeout_seconds=30,
    )
    values = policy.model_dump(mode="python") | {
        "policy_digest": policy.digest_hex(),
        "created_at": datetime.now(UTC),
    }
    values["id"] = values.pop("policy_id")
    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(
                f"INSERT INTO lucy.provider_cost_policies_v1({','.join(values)}) "
                f"VALUES({','.join(f':{name}' for name in values)})"
            ),
            values,
        )
    attempt = ProviderAttemptRequestV1(
        attempt_id=uuid4(),
        idempotency_key="public:cost-restore:1",
        node_id=foundation.node_id,
        channel_binding_id=foundation.channel_binding_id,
        provider=policy.provider,
        model=policy.model,
        rate_version=policy.rate_version,
        request_commitment="a" * 64,
        session_commitment="b" * 64,
        ip_commitment="c" * 64,
        maximum_microusd=5_000,
        input_tokens=100,
        output_tokens=100,
        request_bytes=1_000,
        timeout_seconds=20,
        requested_at=datetime.now(UTC),
    )
    return foundation, attempt


def test_missing_attempt_replays_to_nonexecutable_cost_projection() -> None:
    assert COST_URL is not None and RECOVERY_URL is not None and OWNER_URL is not None
    foundation, attempt = _foundation_policy_attempt()
    admission = ProviderCostAdmissionService(create_session_factory(COST_URL))
    recovery = ProviderCostRecoveryService(create_session_factory(RECOVERY_URL))
    binding = _binding()
    journal = InMemoryRecoveryJournal(binding)
    writer = CostJournalWriter(
        CostJournalPreparationService(create_session_factory(COST_URL)), journal
    )

    reserved = admission.reserve(attempt)
    reservation_digest = writer.append_reservation(reserved)
    recovery.acknowledge(
        attempt_id=attempt.attempt_id,
        event_id=reserved.event_id,
        head_digest=reservation_digest,
    )
    admission.claim_submission(attempt.attempt_id)
    pending = admission.settle(
        attempt_id=attempt.attempt_id,
        incurred_microusd=2_000,
        provider_reference_commitment="e" * 64,
    )
    writer.append_outcome(
        attempt=attempt,
        admission=pending,
        incurred_microusd=2_000,
        provider_reference_commitment="e" * 64,
    )

    # Model a checkpoint from before this attempt; the policy and scope survive.
    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.cost_journal_preparations_v1,lucy.cost_events_v1,"
                "lucy.cost_recovery_outbox_v1,lucy.exposure_reservations_v1,"
                "lucy.provider_attempts_v1 CASCADE"
            )
        )

    restored = PostgresCostReplayStore(create_session_factory(RECOVERY_URL), binding)
    genesis = restored.head()
    reservation_head = restored.apply(journal.event(1), genesis)
    final_head = restored.apply(journal.event(2), reservation_head)
    assert final_head == journal.head()
    assert restored.apply(journal.event(1), genesis) == reservation_head

    with create_engine(OWNER_URL).connect() as connection:
        projection = connection.execute(
            text(
                "SELECT recovery_state,incurred_microusd,unresolved_microusd,"
                "base_attempt_present,source_policy_verified "
                "FROM lucy.restored_cost_exposures_v1 WHERE attempt_id=:attempt"
            ),
            {"attempt": attempt.attempt_id},
        ).one()
        assert projection == ("settlement", 2_000, 0, False, True)
        assert connection.scalar(text("SELECT count(*) FROM lucy.provider_attempts_v1")) == 0

    retry = attempt.model_copy(
        update={"attempt_id": uuid4(), "idempotency_key": "public:cost-restore:blocked"}
    )
    with pytest.raises(DBAPIError, match="cost recovery is not finalized"):
        admission.reserve(retry)


def test_cost_replay_identity_is_execute_only_and_strict() -> None:
    assert APP_URL is not None and COST_URL is not None and RECOVERY_URL is not None
    binding = _binding()
    restored = PostgresCostReplayStore(create_session_factory(RECOVERY_URL), binding)
    with create_engine(APP_URL).connect() as connection, pytest.raises(
        DBAPIError, match="permission denied"
    ):
        connection.execute(text("SELECT lucy.restored_cost_recovery_head_v1()"))
    with create_engine(COST_URL).connect() as connection, pytest.raises(
        DBAPIError, match="permission denied"
    ):
        connection.execute(text("SELECT lucy.restored_cost_recovery_head_v1()"))
    with create_engine(RECOVERY_URL).connect() as connection, pytest.raises(
        DBAPIError, match="permission denied"
    ):
        connection.execute(text("SELECT * FROM lucy.restored_cost_exposures_v1"))
    with pytest.raises(ValueError, match="cost binding"):
        PostgresCostReplayStore(
            create_session_factory(RECOVERY_URL),
            binding.model_copy(update={"stream_kind": RecoveryStreamKind.AUTHORITY}),
        )
    with create_engine(RECOVERY_URL).begin() as connection, pytest.raises(
        DBAPIError, match="cost recovery event is invalid"
    ):
        connection.execute(
            text(
                "SELECT lucy.apply_cost_recovery_event_v1("
                "CAST(:expected AS jsonb),CAST(:event AS jsonb))"
            ),
            {
                "expected": json.dumps(restored.head().model_dump(mode="json")),
                "event": json.dumps({"contract_version": "1", "stream_kind": "cost"}),
            },
        )
