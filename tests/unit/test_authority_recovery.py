from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.authority_recovery import (
    AuthorityTransitionRequestV1,
    AuthorityTransitionResultV1,
    PendingAuthorityEventV1,
)
from lucy.publication import PublicationRejected, PublicProjectionPublisher


def request_values() -> dict[str, object]:
    return {
        "subject_id": uuid4(),
        "actor_id": uuid4(),
        "stream_id": uuid4(),
        "authority_epoch": 1,
        "idempotency_key": "authority:membership:test-1",
        "source_authority_ref": "owner-interaction:test-1",
        "source_authority_digest": "a" * 64,
    }


def result_values() -> dict[str, object]:
    return {
        "event_id": uuid4(),
        "state": "PERSISTENCE_PENDING",
        "stream_id": uuid4(),
        "authority_epoch": 1,
        "event_type": "membership_revoked",
        "security_realm_id": uuid4(),
        "workspace_id": uuid4(),
        "subject_id": uuid4(),
        "previous_generation": 1,
        "new_generation": 2,
        "transition_digest": "b" * 64,
        "journal_sequence": None,
        "journal_event_digest": None,
        "journal_head_digest": None,
        "replayed": False,
    }


def test_transition_request_rejects_content_bearing_or_noncanonical_metadata() -> None:
    AuthorityTransitionRequestV1.model_validate(request_values())
    for update in (
        {"idempotency_key": "contains a space"},
        {"source_authority_ref": "owner proof with content"},
        {"source_authority_digest": "A" * 64},
    ):
        with pytest.raises(ValidationError, match="identifiers"):
            AuthorityTransitionRequestV1.model_validate(request_values() | update)


def test_transition_result_requires_exact_complete_acknowledgement() -> None:
    AuthorityTransitionResultV1.model_validate(result_values())
    durable = result_values() | {
        "state": "DURABLY_RECORDED",
        "journal_sequence": 1,
        "journal_event_digest": "c" * 64,
        "journal_head_digest": "c" * 64,
    }
    AuthorityTransitionResultV1.model_validate(durable)
    with pytest.raises(ValidationError, match="incomplete"):
        AuthorityTransitionResultV1.model_validate(durable | {"journal_head_digest": "d" * 64})
    with pytest.raises(ValidationError, match="exactly once"):
        AuthorityTransitionResultV1.model_validate(result_values() | {"new_generation": 3})


def test_pending_event_requires_aware_time_and_canonical_source() -> None:
    values = result_values() | {
        "idempotency_key": "authority:membership:test-1",
        "source_authority_ref": "owner-interaction:test-1",
        "source_authority_digest": "a" * 64,
        "occurred_at": datetime.now(UTC),
    }
    for field in (
        "state",
        "journal_sequence",
        "journal_event_digest",
        "journal_head_digest",
        "replayed",
    ):
        values.pop(field)
    PendingAuthorityEventV1.model_validate(values)
    with pytest.raises(ValidationError, match="metadata"):
        PendingAuthorityEventV1.model_validate(
            values | {"occurred_at": datetime.now().replace(tzinfo=None)}
        )


def test_obsolete_direct_publication_withdrawal_is_closed() -> None:
    publisher = PublicProjectionPublisher(None)  # type: ignore[arg-type]
    with pytest.raises(PublicationRejected, match="authority transition service"):
        publisher.withdraw(channel_binding_id=uuid4(), actor_id=uuid4())
