from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from lucy.governed_memory import ImportAttemptResultV1
from lucy.memory_extraction import (
    MemoryExtractionCoordinator,
    MemoryExtractionDispatchV1,
    MemoryExtractionProviderOutcomeV1,
    MemoryExtractionUnavailable,
)
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV1
from lucy.secret_filter import MemorySecretDetected

NOW = datetime(2026, 9, 12, 20, 0, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
RESERVATION = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


class AccountingSpy:
    def __init__(self, events: list[str], *, replayed: bool = False) -> None:
        self.events = events
        self.replayed = replayed
        self.settlements: list[tuple[int, str]] = []

    def reserve_attempt(
        self, campaign_id: UUID, *, attempt_key: str, reserved_microusd: int
    ) -> ImportAttemptResultV1:
        assert campaign_id == CAMPAIGN
        assert attempt_key == "pilot:batch-1:attempt-1"
        assert reserved_microusd == 5_000
        self.events.append("reserve")
        return ImportAttemptResultV1(
            reservation_id=RESERVATION, replayed=self.replayed
        )

    def settle_attempt(
        self, reservation_id: UUID, *, billed_microusd: int, result: str
    ) -> ImportAttemptResultV1:
        assert reservation_id == RESERVATION
        self.events.append(f"settle:{result}:{billed_microusd}")
        self.settlements.append((billed_microusd, result))
        return ImportAttemptResultV1(reservation_id=RESERVATION, replayed=False)


class EligibilitySpy:
    def __init__(self, events: list[str], *, fail_phase: str | None = None) -> None:
        self.events = events
        self.fail_phase = fail_phase

    def require_eligible(self, **values: object) -> None:
        phase = str(values["phase"])
        assert values["campaign_id"] == CAMPAIGN
        assert values["source_record_ids"] == ("conversation:node:message",)
        self.events.append(f"eligible:{phase}")
        if phase == self.fail_phase:
            raise PermissionError("synthetic source fence")


class ProviderSpy:
    def __init__(
        self,
        events: list[str],
        *,
        fail: bool = False,
        billed_microusd: int = 2_000,
        provider_policy_id: str = "policy-v1",
        model_route: str = "openrouter/private-model",
    ) -> None:
        self.events = events
        self.fail = fail
        self.billed_microusd = billed_microusd
        self.provider_policy_id = provider_policy_id
        self.model_route = model_route

    def infer(self, **_: object) -> MemoryExtractionProviderOutcomeV1:
        self.events.append("provider")
        if self.fail:
            raise TimeoutError("synthetic ambiguous timeout")
        return MemoryExtractionProviderOutcomeV1(
            output='{"candidates": []}',
            billed_microusd=self.billed_microusd,
            provider_policy_id=self.provider_policy_id,
            model_route=self.model_route,
            provider_reference_commitment="d" * 64,
        )


def _manifest(*, expires_at: datetime | None = None) -> ImportManifestV1:
    return ImportManifestV1(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="pilot:selection",
        parser_version="chatgpt-export-inventory-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="policy-v1",
        model_route="openrouter/private-model",
        records=(
            ImportManifestRecordV1(
                source_record_id="conversation:node:message",
                content_commitment="a" * 64,
                byte_length=17,
                estimated_tokens=6,
                source_revision=1,
                role="owner",
                displayed=True,
            ),
        ),
        max_records=1,
        max_bytes=17,
        max_input_tokens=100,
        max_model_spend_microusd=10_000,
        max_attempts=3,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )


def _dispatch(
    *, prompt: str = "synthetic history", **changes: object
) -> MemoryExtractionDispatchV1:
    values: dict[str, object] = {
        "attempt_key": "pilot:batch-1:attempt-1",
        "source_record_ids": ("conversation:node:message",),
        "prompt": prompt,
        "input_tokens": 20,
        "output_tokens": 50,
        "request_bytes": len(prompt.encode("utf-8")),
        "maximum_microusd": 5_000,
        "timeout_seconds": 30,
    }
    values.update(changes)
    return MemoryExtractionDispatchV1.model_validate(values)


def _coordinator(
    events: list[str],
    *,
    accounting: AccountingSpy | None = None,
    eligibility: EligibilitySpy | None = None,
    provider: ProviderSpy | None = None,
) -> tuple[MemoryExtractionCoordinator, AccountingSpy]:
    selected_accounting = accounting or AccountingSpy(events)
    return (
        MemoryExtractionCoordinator(
            selected_accounting,
            eligibility or EligibilitySpy(events),
            provider or ProviderSpy(events),
            now=lambda: NOW,
        ),
        selected_accounting,
    )


def test_success_rechecks_sources_and_settles_before_returning_output() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(events)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "succeeded"
    assert result.output == '{"candidates": []}'
    assert result.billed_microusd == 2_000
    assert accounting.settlements == [(2_000, "succeeded")]
    assert events == [
        "eligible:admission",
        "reserve",
        "eligible:pre_dispatch",
        "provider",
        "eligible:post_dispatch",
        "settle:succeeded:2000",
    ]


def test_expired_outside_manifest_or_secret_input_never_reserves_or_dispatches() -> None:
    for manifest, dispatch, error in (
        (_manifest(expires_at=NOW), _dispatch(), MemoryExtractionUnavailable),
        (
            _manifest(),
            _dispatch(source_record_ids=("outside:record",)),
            ValueError,
        ),
        (
            _manifest(),
            _dispatch(prompt="api key: synthetic-secret-value-12345"),
            MemorySecretDetected,
        ),
    ):
        events: list[str] = []
        coordinator, _ = _coordinator(events)
        with pytest.raises(error):
            coordinator.execute(manifest=manifest, dispatch=dispatch)
        assert events == []


def test_source_change_before_dispatch_settles_zero_and_blocks_provider() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, eligibility=EligibilitySpy(events, fail_phase="pre_dispatch")
    )

    with pytest.raises(MemoryExtractionUnavailable, match="before provider dispatch"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert accounting.settlements == [(0, "discarded")]
    assert "provider" not in events


def test_source_change_during_call_charges_cost_but_discards_output() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, eligibility=EligibilitySpy(events, fail_phase="post_dispatch")
    )

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "discarded" and result.output is None
    assert accounting.settlements == [(2_000, "discarded")]


def test_provider_failure_charges_full_reservation_and_requires_reconciliation() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, provider=ProviderSpy(events, fail=True)
    )

    with pytest.raises(MemoryExtractionUnavailable, match="full reservation charged"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert accounting.settlements == [(5_000, "failed")]


def test_policy_mismatch_is_billed_and_discarded() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, provider=ProviderSpy(events, provider_policy_id="wrong-policy")
    )

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "discarded" and result.output is None
    assert "policy or model route" in (result.reason or "")
    assert accounting.settlements == [(2_000, "discarded")]


def test_replayed_reservation_never_repeats_provider_execution() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, replayed=True)
    coordinator, _ = _coordinator(events, accounting=accounting)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "reconciliation_required" and result.output is None
    assert events == ["eligible:admission", "reserve"]


def test_provider_over_cap_charges_admitted_maximum_and_returns_no_output() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, provider=ProviderSpy(events, billed_microusd=5_001)
    )

    with pytest.raises(MemoryExtractionUnavailable, match="above admitted maximum"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert accounting.settlements == [(5_000, "failed")]
