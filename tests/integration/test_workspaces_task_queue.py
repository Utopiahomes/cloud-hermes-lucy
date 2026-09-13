from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url

from lucy.db import create_session_factory
from lucy.db.models import (
    RealmBindingRow,
    RealmContentScopeRow,
    RealmServiceBindingRow,
)
from lucy.tenancy import TenancyService
from lucy.workspaces_tasks import PostgresWorkspacesTaskQueue, WorkspacesTaskUnavailable

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
UTOPIA_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
pytestmark = pytest.mark.skipif(not APP_URL, reason="requires PostgreSQL integration database")


@pytest.fixture
def queue_fixture() -> tuple[PostgresWorkspacesTaskQueue, object, object]:
    assert APP_URL and OWNER_URL and UTOPIA_URL
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host) != ("lucy_test", "127.0.0.1") or parsed.port not in {
        54329,
        54339,
    }:
        raise RuntimeError("refusing to modify a non-synthetic database")
    app_sessions = create_session_factory(APP_URL)
    owner_sessions = create_session_factory(OWNER_URL)
    runtime_sessions = create_session_factory(UTOPIA_URL)
    with owner_sessions.begin() as session:
        session.execute(
            text(
                "TRUNCATE lucy.workspaces_task_events_v1,lucy.workspaces_tasks_v1,"
                "lucy.realm_service_bindings_v1,lucy.realm_content_scopes_v1,"
                "lucy.channel_bindings,lucy.workspaces,lucy.realm_bindings,"
                "lucy.node_tenures,lucy.security_realms,lucy.nodes,"
                "lucy.tenant_accounts,lucy.principals CASCADE"
            )
        )
    tenancy = TenancyService(app_sessions)
    foundation = tenancy.create_node_foundation(
        account_slug="workspaces-queue",
        account_name="Workspaces Queue",
        node_slug="utopia-workspaces-queue",
        node_name="Utopia Workspaces Queue",
        node_kind="organization",
        realm_slug="utopia-workspaces-queue-realm",
        workspace_slug="operations",
        hostname="internal.workspaces-queue.test",
        workspace_kind="private",
        channel_kind="internal",
    )
    service_principal_id = tenancy.create_principal(
        issuer="https://workload.test",
        subject="render:utopia:workspaces",
        kind="service",
        display_name="Utopia Workspaces Lucy",
    )
    with app_sessions() as session:
        realm_binding = session.execute(
            select(RealmBindingRow).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    content_scope_id, binding_id = uuid4(), uuid4()
    with owner_sessions.begin() as session:
        session.add(
            RealmContentScopeRow(
                id=content_scope_id,
                tenant_account_id=foundation.account_id,
                node_id=foundation.node_id,
                node_tenure_id=foundation.tenure_id,
                tenure_epoch=1,
                security_realm_id=foundation.realm_id,
                storage_epoch=1,
                realm_binding_id=realm_binding.id,
                workspace_id=foundation.workspace_id,
                deployment_id=uuid4(),
                created_at=datetime.now(UTC),
            )
        )
        session.flush()
        session.add(
            RealmServiceBindingRow(
                id=binding_id,
                session_login="lucy_utopia_routine",
                service_principal_id=service_principal_id,
                content_scope_id=content_scope_id,
                service_role="realm_routine",
                allowed_actions=["task.delegate", "task.execute"],
                binding_generation=1,
                node_authz_epoch=1,
                policy_version=1,
                active=True,
                created_at=datetime.now(UTC),
            )
        )
        session.execute(
            text(
                "GRANT EXECUTE ON FUNCTION "
                "lucy.enqueue_workspaces_task_v1(uuid,uuid,uuid,uuid,uuid,text,text),"
                "lucy.claim_workspaces_task_v1(uuid,integer),"
                "lucy.heartbeat_workspaces_task_v1(uuid,uuid,integer),"
                "lucy.complete_workspaces_task_v1(uuid,uuid,text,jsonb) "
                "TO lucy_utopia_routine"
            )
        )
    context = SimpleNamespace(
        service_binding_id=binding_id,
        workspace_id=foundation.workspace_id,
        channel_binding_id=foundation.channel_binding_id,
    )
    return PostgresWorkspacesTaskQueue(runtime_sessions), context, owner_sessions


def test_idempotent_queue_claim_lease_and_terminal_replay(queue_fixture) -> None:
    queue, context, owner_sessions = queue_fixture
    request_id, room_id, worker_id = uuid4(), uuid4(), uuid4()
    first = queue.delegate(
        context=context,
        request_id=request_id,
        room_id=room_id,
        instruction="Draft a viewing plan",
    )
    assert queue.delegate(
        context=context,
        request_id=request_id,
        room_id=room_id,
        instruction="Draft a viewing plan",
    ) == first
    with pytest.raises(WorkspacesTaskUnavailable):
        queue.delegate(
            context=context,
            request_id=request_id,
            room_id=room_id,
            instruction="Changed instruction",
        )

    claim = queue.claim(worker_id=worker_id, lease_seconds=30)
    assert claim is not None and claim.task_id == first and claim.attempt == 1
    assert queue.claim(worker_id=worker_id, lease_seconds=30) is None
    assert queue.heartbeat(
        task_id=first, lease_token=claim.lease_token, lease_seconds=30
    ) > datetime.now(UTC)

    with owner_sessions.begin() as session:
        session.execute(
            text(
                "UPDATE lucy.workspaces_tasks_v1 "
                "SET lease_expires_at=:expired WHERE id=:task_id"
            ),
            {"expired": datetime.now(UTC) - timedelta(seconds=1), "task_id": first},
        )
    second_claim = queue.claim(worker_id=worker_id, lease_seconds=30)
    assert second_claim is not None and second_claim.attempt == 2
    assert second_claim.lease_token != claim.lease_token
    with pytest.raises(WorkspacesTaskUnavailable):
        queue.complete(
            task_id=first,
            lease_token=claim.lease_token,
            outcome="completed",
            result={"artifact_id": str(UUID(int=1))},
        )
    result = {"artifact_id": str(UUID(int=1))}
    assert queue.complete(
        task_id=first,
        lease_token=second_claim.lease_token,
        outcome="completed",
        result=result,
    ) is False
    assert queue.complete(
        task_id=first,
        lease_token=second_claim.lease_token,
        outcome="completed",
        result=result,
    ) is True

    with owner_sessions() as session:
        task = session.execute(
            text(
                "SELECT status,attempt_count,result FROM lucy.workspaces_tasks_v1 "
                "WHERE id=:task_id"
            ),
            {"task_id": first},
        ).one()
        events = list(
            session.scalars(
                text(
                    "SELECT event_type FROM lucy.workspaces_task_events_v1 "
                    "WHERE task_id=:task_id ORDER BY occurred_at"
                ),
                {"task_id": first},
            )
        )
    assert task == ("completed", 2, result)
    assert events == ["enqueued", "claimed", "heartbeat", "claimed", "completed"]
