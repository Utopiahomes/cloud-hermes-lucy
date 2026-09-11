from __future__ import annotations

from datetime import UTC, datetime
from itertools import count
from uuid import UUID

import pytest

from deploy.postgres.build_recovery_drill_manifests_v1_3 import (
    RecoveryDrillManifestError,
    build_events,
    build_fixture,
    refresh_events,
)
from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind
from tests.unit.test_realm_foundation_provisioner import _stamp


def _uuids():
    values = count(1)

    def next_uuid() -> UUID:
        return UUID(int=next(values))

    return next_uuid


def _binding(digest: str) -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=RecoveryStreamKind.AUTHORITY,
        stream_id=UUID(int=100),
        authority_epoch=1,
        independent_store_id="arn:aws:dynamodb:us-east-1:123456789012:table/authority",
        writer_identity="arn:aws:iam::123456789012:role/authority-writer",
        recovery_identity="arn:aws:iam::123456789012:role/recovery",
        binding_manifest_digest=digest,
    )


def test_builds_distinct_content_free_fixture() -> None:
    stamp = _stamp()
    fixture = build_fixture(
        stamp, created_at=datetime(2026, 9, 10, tzinfo=UTC), new_uuid=_uuids()
    )
    identifiers = {
        fixture.owner_principal_id,
        fixture.owner_membership_id,
        fixture.member_principal_id,
        fixture.member_membership_id,
        fixture.channel_binding_id,
        fixture.policy_id,
    }
    assert len(identifiers) == 6
    assert fixture.hostname == "synthetic-recovery-utopia.invalid"
    assert fixture.provider == "openrouter"


def test_event_manifest_is_fixture_and_binding_bound() -> None:
    stamp = _stamp()
    fixture = build_fixture(
        stamp, created_at=datetime(2026, 9, 10, tzinfo=UTC), new_uuid=_uuids()
    )
    binding = _binding("a" * 64)
    events = build_events(
        stamp,
        fixture,
        binding,
        binding_manifest_digest=binding.binding_manifest_digest,
        created_at=datetime(2026, 9, 10, 1, tzinfo=UTC),
        new_uuid=_uuids(),
    )
    assert events.fixture_manifest_digest == fixture.digest_hex()
    assert events.authority_idempotency_key.startswith("synthetic:recovery:authority:")
    assert len({events.request_commitment, events.session_commitment, events.ip_commitment}) == 3


def test_event_manifest_rejects_binding_substitution() -> None:
    stamp = _stamp()
    fixture = build_fixture(
        stamp, created_at=datetime(2026, 9, 10, tzinfo=UTC), new_uuid=_uuids()
    )
    with pytest.raises(RecoveryDrillManifestError):
        build_events(
            stamp,
            fixture,
            _binding("a" * 64),
            binding_manifest_digest="b" * 64,
            created_at=datetime(2026, 9, 10, 1, tzinfo=UTC),
            new_uuid=_uuids(),
        )


def test_refresh_preserves_event_identity_and_updates_only_admission_time() -> None:
    stamp = _stamp()
    fixture = build_fixture(
        stamp, created_at=datetime(2026, 9, 10, tzinfo=UTC), new_uuid=_uuids()
    )
    binding = _binding("a" * 64)
    previous = build_events(
        stamp,
        fixture,
        binding,
        binding_manifest_digest=binding.binding_manifest_digest,
        created_at=datetime(2026, 9, 10, 1, tzinfo=UTC),
        new_uuid=_uuids(),
    )
    refreshed = refresh_events(
        stamp,
        fixture,
        binding,
        previous,
        binding_manifest_digest=binding.binding_manifest_digest,
        created_at=datetime(2026, 9, 10, 2, tzinfo=UTC),
    )
    assert refreshed.requested_at != previous.requested_at
    assert refreshed.model_dump(exclude={"requested_at"}) == previous.model_dump(
        exclude={"requested_at"}
    )


def test_manifest_builder_rejects_naive_time() -> None:
    with pytest.raises(RecoveryDrillManifestError):
        build_fixture(_stamp(), created_at=datetime(2026, 9, 10), new_uuid=_uuids())
