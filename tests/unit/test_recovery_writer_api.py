from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

import lucy.recovery_writer_api as api
import lucy.recovery_writer_runtime as runtime
from lucy.recovery_journal import (
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalHeadV1,
    RecoveryStreamKind,
)


class FakeJournal:
    def __init__(self, head: RecoveryJournalHeadV1) -> None:
        self.value = head
        self.head_reads = 0

    def head(self) -> RecoveryJournalHeadV1:
        self.head_reads += 1
        return self.value


class FakeWriter:
    def __init__(self, acknowledgement: RecoveryAppendAcknowledgementV1) -> None:
        self.acknowledgement = acknowledgement
        self.received: UUID | None = None

    def append_pending(self, event_id: UUID) -> RecoveryAppendAcknowledgementV1:
        self.received = event_id
        return self.acknowledgement


def _dependencies(
    kind: RecoveryStreamKind = RecoveryStreamKind.AUTHORITY,
) -> api.RecoveryWriterDependencies:
    event_id = uuid4()
    digest = "a" * 64
    head = RecoveryJournalHeadV1(
        stream_kind=kind,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
        binding_manifest_digest="b" * 64,
        sequence=1,
        event_digest=digest,
    )
    acknowledgement = RecoveryAppendAcknowledgementV1(
        event_id=event_id,
        event_digest=digest,
        resulting_head=head,
        acknowledged_at=datetime.now(UTC),
    )
    return api.RecoveryWriterDependencies(
        stream_kind=kind,
        writer=FakeWriter(acknowledgement),  # type: ignore[arg-type]
        journal=FakeJournal(head),  # type: ignore[arg-type]
    )


def test_writer_endpoint_accepts_only_empty_exact_event_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependencies = _dependencies()
    event_id = dependencies.writer.acknowledgement.event_id  # type: ignore[attr-defined]
    monkeypatch.setenv("LUCY_RECOVERY_WRITER_TOKEN", "authority-writer-only")
    monkeypatch.setattr(api, "_dependencies", lambda: dependencies)
    client = TestClient(api.app)
    path = f"/v1/recovery/events/{event_id}"

    assert client.post(path).status_code == 401
    headers = {"Authorization": "Bearer authority-writer-only"}
    assert client.post(path, headers=headers, json={"digest": "forbidden"}).status_code == 400
    response = client.post(path, headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "event_id": str(event_id),
        "stream_kind": "authority",
        "sequence": 1,
        "event_digest": "a" * 64,
    }
    assert dependencies.writer.received == event_id  # type: ignore[attr-defined]


def test_writer_instance_is_pinned_to_one_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_RECOVERY_WRITER_STREAM", "authority")
    assert api._stream_kind() is RecoveryStreamKind.AUTHORITY
    monkeypatch.setenv("LUCY_RECOVERY_WRITER_STREAM", "cost")
    assert api._stream_kind() is RecoveryStreamKind.COST
    monkeypatch.setenv("LUCY_RECOVERY_WRITER_STREAM", "other")
    with pytest.raises(Exception, match="stream is invalid"):
        api._stream_kind()


def test_writer_runtime_requires_capture_off_and_verified_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false")
    monkeypatch.setenv("LUCY_OBSERVED_HERMES_COMMIT", "a" * 40)
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    dependencies = _dependencies()
    monkeypatch.setattr(runtime, "_dependencies", lambda: dependencies)
    calls: list[str] = []
    monkeypatch.setattr(
        runtime.uvicorn, "run", lambda app, **_kwargs: calls.append(app.title)
    )
    runtime.main()
    assert calls == ["Lucy Recovery Journal Writer API"]
    assert dependencies.journal.head_reads == 1  # type: ignore[attr-defined]

    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true")
    with pytest.raises(SystemExit, match="startup gate failed"):
        runtime.main()
