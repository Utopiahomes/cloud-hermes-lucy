from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.cost_admission import (
    ProviderAttemptRequestV1,
    ProviderCostAdmissionService,
    ProviderCostPolicyV1,
    ProviderCostRecoveryService,
)

ROOT = Path(__file__).resolve().parents[2]


def _policy(**changes: object) -> ProviderCostPolicyV1:
    values: dict[str, object] = {
        "policy_id": uuid4(),
        "version": 1,
        "node_id": uuid4(),
        "channel_binding_id": uuid4(),
        "provider": "openrouter",
        "model": "openai/gpt-oss-20b",
        "rate_version": "openrouter-2026-09-10",
        "effective_at": datetime.now(UTC),
        "kill_state": "enabled",
        "platform_daily_cap_microusd": 1_000_000,
        "node_daily_cap_microusd": 500_000,
        "site_daily_cap_microusd": 250_000,
        "provider_daily_cap_microusd": 750_000,
        "outstanding_cap_microusd": 100_000,
        "concurrency_limit": 4,
        "requests_per_minute": 20,
        "session_requests_per_minute": 5,
        "ip_requests_per_minute": 10,
        "per_request_cap_microusd": 25_000,
        "max_input_tokens": 4_000,
        "max_output_tokens": 1_000,
        "max_request_bytes": 32_000,
        "timeout_seconds": 60,
    }
    values.update(changes)
    return ProviderCostPolicyV1.model_validate(values)


def test_cost_policy_is_complete_immutable_and_digest_stable() -> None:
    policy = _policy()
    assert policy.digest_hex() == policy.digest_hex()
    with pytest.raises(ValidationError):
        _policy(per_request_cap_microusd=100_001)
    with pytest.raises(ValidationError):
        _policy(requests_per_minute=0)


def test_provider_attempt_rejects_plain_or_noncanonical_identifiers() -> None:
    values = {
        "attempt_id": uuid4(),
        "idempotency_key": "public:synthetic:1",
        "node_id": uuid4(),
        "channel_binding_id": uuid4(),
        "provider": "openrouter",
        "model": "openai/gpt-oss-20b",
        "rate_version": "openrouter-2026-09-10",
        "request_commitment": "a" * 64,
        "session_commitment": "b" * 64,
        "ip_commitment": "c" * 64,
        "maximum_microusd": 5_000,
        "input_tokens": 100,
        "output_tokens": 100,
        "request_bytes": 1_000,
        "timeout_seconds": 30,
        "requested_at": datetime.now(UTC),
    }
    ProviderAttemptRequestV1.model_validate(values)
    with pytest.raises(ValidationError):
        ProviderAttemptRequestV1.model_validate({**values, "ip_commitment": "203.0.113.4"})
    with pytest.raises(ValidationError):
        ProviderAttemptRequestV1.model_validate(
            {**values, "requested_at": datetime.now().replace(tzinfo=None)}
        )


def test_cost_migration_has_separate_execute_only_boundaries() -> None:
    source = (ROOT / "migrations/versions/0043_r1_provider_cost_admission.py").read_text(
        encoding="utf-8"
    )
    assert '("lucy_cost_admission",)' in source
    assert '("lucy_cost_recovery_writer",)' in source
    assert "FROM PUBLIC, lucy_app, lucy_public_runtime" in source
    assert "state='OVER_CAP'" in source
    assert "unresolved_microusd>0" in source
    assert "v_outstanding+p_maximum_microusd" in source
    assert "v_concurrency>=v_policy.concurrency_limit" in source
    assert "provider_attempt idempotency conflict" not in source
    assert "provider attempt idempotency conflict" in source


def test_cost_outcome_migration_requires_independent_ack_before_release() -> None:
    source = (ROOT / "migrations/versions/0044_r1_cost_outcome_recovery.py").read_text(
        encoding="utf-8"
    )
    pending = source.index("SET state=v_pending")
    acknowledgement = source.index("CREATE FUNCTION lucy.acknowledge_provider_outcome_v1")
    release = source.index("unresolved_microusd=0", acknowledgement)
    assert pending < acknowledgement < release
    assert "TO lucy_cost_recovery_writer" in source
    assert "FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_admission" in source


def test_cost_clients_do_not_expose_each_others_privileged_operations() -> None:
    assert not hasattr(ProviderCostAdmissionService, "acknowledge")
    assert not hasattr(ProviderCostAdmissionService, "acknowledge_outcome")
    assert not hasattr(ProviderCostRecoveryService, "reserve")
    assert not hasattr(ProviderCostRecoveryService, "settle")
