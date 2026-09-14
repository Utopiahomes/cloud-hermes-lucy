from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from lucy.workspaces_tasks import PostgresWorkspacesTaskQueue

ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")
THREE = UUID("00000000-0000-4000-8000-000000000003")
FOUR = UUID("00000000-0000-4000-8000-000000000004")


class FakeSession:
    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.calls: list[tuple[str, dict[str, object]]] = []

    def scalar(self, statement: object, parameters: dict[str, object]) -> object:
        self.calls.append((str(statement), parameters))
        return self.values.pop(0)


class FakeSessions:
    def __init__(self, *values: object) -> None:
        self.session = FakeSession(list(values))

    @contextmanager
    def begin(self):
        yield self.session


def test_enqueue_binds_admitted_context_and_returns_durable_id() -> None:
    sessions = FakeSessions({"task_id": str(FOUR), "replayed": False})
    queue = PostgresWorkspacesTaskQueue(sessions)  # type: ignore[arg-type]
    context = SimpleNamespace(
        service_binding_id=ONE,
        workspace_id=TWO,
        channel_binding_id=THREE,
    )

    task_id = queue.delegate(
        context=context,  # type: ignore[arg-type]
        request_id=THREE,
        room_id=FOUR,
        instruction="Draft a viewing plan",
    )

    assert task_id == FOUR
    statement, values = sessions.session.calls[0]
    assert "enqueue_workspaces_task_v1" in statement
    assert values["service_binding_id"] == ONE
    assert values["workspace_id"] == TWO
    assert values["channel_binding_id"] == THREE
    assert values["room_id"] == FOUR
    assert len(str(values["instruction_digest"])) == 64


def test_claim_returns_opaque_lease_and_none_when_queue_is_empty() -> None:
    expiry = datetime(2026, 9, 12, 19, 0, tzinfo=UTC)
    sessions = FakeSessions(
        {
            "task_id": str(ONE),
            "request_id": str(TWO),
            "room_id": str(THREE),
            "instruction": "Draft a viewing plan",
            "attempt": 1,
            "lease_token": str(FOUR),
            "lease_expires_at": expiry.isoformat(),
        },
        None,
    )
    queue = PostgresWorkspacesTaskQueue(sessions)  # type: ignore[arg-type]

    claim = queue.claim(worker_id=ONE, lease_seconds=45)
    assert claim is not None
    assert claim.task_id == ONE
    assert claim.lease_token == FOUR
    assert claim.lease_expires_at == expiry
    assert queue.claim(worker_id=ONE) is None


def test_heartbeat_and_completion_use_exact_lease_token() -> None:
    expiry = datetime(2026, 9, 12, 19, 0, tzinfo=UTC)
    sessions = FakeSessions(
        {"task_id": str(ONE), "lease_expires_at": expiry.isoformat()},
        {"task_id": str(ONE), "replayed": True},
    )
    queue = PostgresWorkspacesTaskQueue(sessions)  # type: ignore[arg-type]

    assert queue.heartbeat(task_id=ONE, lease_token=TWO) == expiry
    assert queue.complete(
        task_id=ONE,
        lease_token=TWO,
        outcome="completed",
        result={"artifact_id": str(THREE)},
    ) is True
    assert sessions.session.calls[0][1]["lease_token"] == TWO
    assert "complete_workspaces_task_v1" in sessions.session.calls[1][0]


def test_task_bounds_are_enforced_before_database_access() -> None:
    queue = PostgresWorkspacesTaskQueue(FakeSessions())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="between 15 and 300"):
        queue.claim(worker_id=ONE, lease_seconds=5)
    with pytest.raises(ValueError, match="65536"):
        queue.complete(
            task_id=ONE,
            lease_token=TWO,
            outcome="completed",
            result={"payload": "x" * 70_000},
        )


def test_migration_keeps_queue_execute_only_and_lease_fenced() -> None:
    paths = tuple(
        __import__("pathlib")
        .Path("migrations/versions")
        .glob("*_workspaces_task_queue.py")
    )
    assert len(paths) == 1
    source = paths[0].read_text(encoding="utf-8")
    assert "allowed_actions @> '[\"task.delegate\"]'::jsonb" in source
    assert "allowed_actions @> '[\"task.execute\"]'::jsonb" in source
    assert "allowed_actions @> '[\"memory.read\"]'::jsonb" in source
    assert "DISABLE TRIGGER realm_service_binding_monotonic" in source
    assert "FOR UPDATE SKIP LOCKED" in source
    assert "lease_token=p_lease_token AND lease_expires_at>v_now" in source
    assert "uq_workspaces_task_request" in source
    assert "REVOKE ALL ON lucy.workspaces_tasks_v1" in source
    assert "workspaces_task_events_immutable" in source
