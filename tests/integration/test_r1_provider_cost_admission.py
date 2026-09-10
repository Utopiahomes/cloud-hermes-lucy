from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from lucy.cost_admission import (
    ProviderAttemptRequestV1,
    ProviderCostAdmissionService,
    ProviderCostPolicyV1,
)
from lucy.db import create_session_factory
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
COST_URL = os.getenv("LUCY_TEST_COST_DATABASE_URL")
RECOVERY_URL = os.getenv("LUCY_TEST_COST_RECOVERY_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not all((APP_URL, OWNER_URL, COST_URL, RECOVERY_URL)),
    reason="requires PostgreSQL cost-admission integration database",
)


@pytest.fixture(autouse=True)
def clean_cost_tables() -> None:
    assert OWNER_URL is not None
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        if connection.scalar(text("SELECT current_database()")) != "lucy_test":
            raise RuntimeError("refusing to clear a non-synthetic database")
        connection.execute(
            text(
                "TRUNCATE lucy.cost_events_v1,lucy.cost_recovery_outbox_v1,"
                "lucy.exposure_reservations_v1,lucy.provider_attempts_v1,"
                "lucy.provider_cost_policies_v1,lucy.public_projection_events,"
                "lucy.public_projection_routes,lucy.public_projection_versions,"
                "lucy.public_projection_approvals,lucy.public_projection_candidates,"
                "lucy.lucy_instances,lucy.node_memberships,lucy.channel_bindings,"
                "lucy.wallet_registrations,lucy.workspaces,lucy.realm_bindings,"
                "lucy.node_tenures,lucy.security_realms,lucy.nodes,"
                "lucy.tenant_accounts,lucy.principals CASCADE"
            )
        )
    engine.dispose()


def _foundation_and_policy(*, concurrency: int = 2, outstanding: int = 10_000):
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
        outstanding_cap_microusd=outstanding,
        concurrency_limit=concurrency,
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
    columns = ",".join(values)
    parameters = ",".join(f":{name}" for name in values)
    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(f"INSERT INTO lucy.provider_cost_policies_v1({columns}) VALUES({parameters})"),
            values,
        )
    return foundation, policy


def _request(foundation, *, key: str, maximum: int = 5_000) -> ProviderAttemptRequestV1:
    return ProviderAttemptRequestV1(
        attempt_id=uuid4(),
        idempotency_key=key,
        node_id=foundation.node_id,
        channel_binding_id=foundation.channel_binding_id,
        provider="openrouter",
        model="openai/gpt-oss-20b",
        rate_version="synthetic-v1",
        request_commitment="a" * 64,
        session_commitment="b" * 64,
        ip_commitment="c" * 64,
        maximum_microusd=maximum,
        input_tokens=100,
        output_tokens=100,
        request_bytes=1_000,
        timeout_seconds=20,
        requested_at=datetime.now(UTC),
    )


def test_unknown_exposure_survives_rollover_and_retry_never_resubmits() -> None:
    assert COST_URL is not None and RECOVERY_URL is not None and OWNER_URL is not None
    foundation, _ = _foundation_and_policy(outstanding=5_000)
    admission = ProviderCostAdmissionService(create_session_factory(COST_URL))
    recovery = ProviderCostAdmissionService(create_session_factory(RECOVERY_URL))
    request = _request(foundation, key="public:unknown:1")

    pending = admission.reserve(request)
    assert pending.state == "PERSISTENCE_PENDING"
    with pytest.raises(DBAPIError, match="not admitted"):
        admission.claim_submission(request.attempt_id)
    admitted = recovery.acknowledge(
        attempt_id=request.attempt_id,
        event_id=pending.event_id,
        head_digest="d" * 64,
    )
    assert admitted.state == "ADMITTED"
    assert admission.claim_submission(request.attempt_id).state == "SUBMITTED"
    assert admission.mark_unknown(request.attempt_id).state == "UNKNOWN"
    replay = admission.reserve(request)
    assert replay.replayed and replay.state == "UNKNOWN"

    with create_engine(OWNER_URL).begin() as connection:
        connection.execute(
            text(
                "UPDATE lucy.provider_attempts_v1 "
                "SET admission_period=admission_period-interval '1 day' WHERE id=:id"
            ),
            {"id": request.attempt_id},
        )
    with pytest.raises(DBAPIError, match="limit exceeded"):
        admission.reserve(_request(foundation, key="public:unknown:2"))


def test_concurrent_attempts_cannot_oversubscribe_outstanding_cap() -> None:
    assert COST_URL is not None
    foundation, _ = _foundation_and_policy(concurrency=5, outstanding=5_000)

    def reserve(key: str) -> str:
        service = ProviderCostAdmissionService(create_session_factory(COST_URL))
        try:
            return service.reserve(_request(foundation, key=key, maximum=4_000)).state
        except DBAPIError:
            return "DENIED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, ("public:race:1", "public:race:2")))
    assert sorted(results) == ["DENIED", "PERSISTENCE_PENDING"]

    engine = create_engine(COST_URL)
    with pytest.raises(DBAPIError, match="permission denied"), engine.begin() as connection:
        connection.execute(text("SELECT * FROM lucy.provider_attempts_v1"))
    engine.dispose()
