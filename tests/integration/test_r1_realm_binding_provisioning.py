from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import select
from sqlalchemy.engine import make_url

from deploy.postgres.provision_realm_bindings_v1_3 import (
    RealmProvisioningError,
    apply_manifest,
)
from deploy.postgres.provision_realm_foundation_v1_3 import (
    RealmFoundationSeedV1,
    apply_foundation,
)
from lucy.db import create_session_factory
from lucy.db.models import RealmBindingRow
from lucy.realm_provisioning import RealmExecutorStampV1, RealmSecurityStampV1
from lucy.tenancy import TenancyService

OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="requires PostgreSQL integration database")
ACCOUNT = "123456789012"


def _conninfo() -> str:
    assert OWNER_URL is not None
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to provision outside the disposable test database")
    return parsed.set(drivername="postgresql").render_as_string(hide_password=False)


def _executor(label: str, suffix: str) -> RealmExecutorStampV1:
    return RealmExecutorStampV1(
        binding_id=uuid4(),
        caller_identity=f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-{label}",
        executor_identity=f"lucy-utopia-{label}",
        executor_alias_arn=(
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-utopia-{label}:production"
        ),
        executor_version=1,
        receipt_key_id=(
            f"arn:aws:kms:us-east-1:{ACCOUNT}:"
            f"key/00000000-0000-4000-8000-00000000000{suffix}"
        ),
    )


def _stamp() -> RealmSecurityStampV1:
    assert OWNER_URL is not None
    sessions = create_session_factory(OWNER_URL)
    tenancy = TenancyService(sessions)
    foundation = tenancy.create_node_foundation(
        account_slug="realm-stamp-test",
        account_name="Realm stamp test",
        node_slug="realm-stamp-test",
        node_name="Realm stamp test",
        node_kind="organization",
        realm_slug="utopia",
        workspace_slug="private",
        hostname="realm-stamp.test",
        workspace_kind="private",
        channel_kind="internal",
    )
    principals = {
        role: tenancy.create_principal(
            issuer="https://workload.test",
            subject=f"render:utopia:{role}",
            kind="service",
            display_name=f"Utopia {role}",
        )
        for role in ("routine", "policy", "workflow", "finality")
    }
    with sessions() as session:
        realm_binding_id = session.execute(
            select(RealmBindingRow.id).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    sessions.kw["bind"].dispose()
    return RealmSecurityStampV1(
        realm_slug="utopia",
        aws_account_id=ACCOUNT,
        content_scope_id=uuid4(),
        tenant_account_id=foundation.account_id,
        node_id=foundation.node_id,
        node_tenure_id=foundation.tenure_id,
        tenure_epoch=1,
        security_realm_id=foundation.realm_id,
        storage_epoch=1,
        realm_binding_id=realm_binding_id,
        workspace_id=foundation.workspace_id,
        deployment_id=uuid4(),
        service_binding_id=uuid4(),
        routine_login="lucy_utopia_routine",
        routine_principal_id=principals["routine"],
        archive_actor_binding_id=uuid4(),
        policy_login="lucy_utopia_policy",
        policy_principal_id=principals["policy"],
        policy_actor_binding_id=uuid4(),
        workflow_login="lucy_utopia_sensitive_workflow",
        workflow_principal_id=principals["workflow"],
        workflow_actor_binding_id=uuid4(),
        finality_login="lucy_utopia_finality",
        finality_principal_id=principals["finality"],
        finality_actor_binding_id=uuid4(),
        binding_generation=1,
        node_authz_epoch=1,
        policy_version=1,
        retrieval_executor=_executor("retrieval", "1"),
        deletion_executor=_executor("deletion", "2"),
    )


@pytest.fixture(autouse=True)
def clean_realm_directory() -> None:
    with psycopg.connect(_conninfo()) as connection:
        connection.execute(
            "TRUNCATE lucy.realm_executor_bindings_v2, "
            "lucy.realm_sensitive_actor_bindings_v1, lucy.realm_service_bindings_v1, "
            "lucy.realm_content_scopes_v1, lucy.channel_bindings, "
            "lucy.wallet_registrations, lucy.workspaces, lucy.realm_bindings, "
            "lucy.node_tenures, lucy.security_realms, lucy.nodes, "
            "lucy.tenant_accounts, lucy.principals CASCADE"
        )


def test_partial_realm_stamp_fails_without_completing_bindings() -> None:
    stamp = _stamp()
    with psycopg.connect(_conninfo()) as connection:
        # A partial earlier attempt must not be silently completed from an unreviewed state.
        connection.execute(
            "INSERT INTO lucy.realm_content_scopes_v1 VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                stamp.content_scope_id,
                stamp.tenant_account_id,
                stamp.node_id,
                stamp.node_tenure_id,
                stamp.tenure_epoch,
                stamp.security_realm_id,
                stamp.storage_epoch,
                stamp.realm_binding_id,
                stamp.workspace_id,
                stamp.deployment_id,
                datetime.now(UTC),
            ),
        )
    with (
        pytest.raises(RealmProvisioningError, match="partially"),
        psycopg.connect(_conninfo()) as connection,
    ):
        apply_manifest(connection, stamp)
    with psycopg.connect(_conninfo()) as connection:
        assert connection.execute(
            "SELECT (SELECT count(*) FROM lucy.realm_content_scopes_v1),"
            "(SELECT count(*) FROM lucy.realm_service_bindings_v1),"
            "(SELECT count(*) FROM lucy.realm_sensitive_actor_bindings_v1),"
            "(SELECT count(*) FROM lucy.realm_executor_bindings_v2)"
        ).fetchone() == (1, 0, 0, 0)


def test_exact_realm_stamp_is_idempotent() -> None:
    stamp = _stamp()
    with psycopg.connect(_conninfo()) as connection:
        assert apply_manifest(connection, stamp) is True
    with psycopg.connect(_conninfo()) as connection:
        assert apply_manifest(connection, stamp) is False
        assert connection.execute(
            "SELECT (SELECT count(*) FROM lucy.realm_content_scopes_v1),"
            "(SELECT count(*) FROM lucy.realm_service_bindings_v1),"
            "(SELECT count(*) FROM lucy.realm_sensitive_actor_bindings_v1),"
            "(SELECT count(*) FROM lucy.realm_executor_bindings_v2)"
        ).fetchone() == (1, 1, 4, 2)


def test_exact_foundation_replays_and_admits_the_security_stamp() -> None:
    stamp = _stamp()
    seed = RealmFoundationSeedV1(
        realm_slug="utopia",
        account_slug="realm-stamp-test",
        account_display_name="Realm stamp test",
        node_slug="realm-stamp-test",
        node_display_name="Realm stamp test",
        node_kind="organization",
        workspace_slug="private",
        service_issuer="lucy://utopia/services",
        wallet_id=uuid4(),
        provisioned_at=datetime(2026, 9, 9, tzinfo=UTC),
    )
    with psycopg.connect(_conninfo()) as connection:
        connection.execute(
            "TRUNCATE lucy.realm_executor_bindings_v2, "
            "lucy.realm_sensitive_actor_bindings_v1, lucy.realm_service_bindings_v1, "
            "lucy.realm_content_scopes_v1, lucy.channel_bindings, "
            "lucy.wallet_registrations, lucy.workspaces, lucy.realm_bindings, "
            "lucy.node_tenures, lucy.security_realms, lucy.nodes, "
            "lucy.tenant_accounts, lucy.principals CASCADE"
        )
    with psycopg.connect(_conninfo()) as connection:
        assert apply_foundation(connection, stamp, seed) is True
    with psycopg.connect(_conninfo()) as connection:
        assert apply_foundation(connection, stamp, seed) is False
        assert apply_manifest(connection, stamp) is True
        assert connection.execute(
            "SELECT (SELECT count(*) FROM lucy.tenant_accounts),"
            "(SELECT count(*) FROM lucy.nodes),"
            "(SELECT count(*) FROM lucy.node_tenures),"
            "(SELECT count(*) FROM lucy.security_realms),"
            "(SELECT count(*) FROM lucy.realm_bindings),"
            "(SELECT count(*) FROM lucy.workspaces),"
            "(SELECT count(*) FROM lucy.wallet_registrations),"
            "(SELECT count(*) FROM lucy.principals),"
            "(SELECT count(*) FROM lucy.channel_bindings),"
            "(SELECT count(*) FROM lucy.node_memberships)"
        ).fetchone() == (1, 1, 1, 1, 1, 1, 1, 4, 0, 0)
