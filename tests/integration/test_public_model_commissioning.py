from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from deploy.postgres import commission_public_model_staging_v1 as commissioning
from deploy.postgres.commission_public_model_staging_v1 import (
    LOGIN,
    PublicModelCommissioningConfig,
    _conninfo,
    commission,
)
from lucy.db import create_session_factory
from lucy.public_model_activation import UtopiaPublicModelActivationManifestV2
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not all((APP_URL, OWNER_URL)),
    reason="requires disposable PostgreSQL integration database",
)


def _manifest(node_id: object, channel_binding_id: object) -> UtopiaPublicModelActivationManifestV2:
    return UtopiaPublicModelActivationManifestV2.model_validate(
        {
            "contract": "lucy.utopia.public-model.activation-manifest.v2",
            "environment": "production",
            "realm_slug": "utopia",
            "release_state": "staging-test",
            "release_decision_id": "synthetic-public-model-commissioning",
            "artifacts": {
                "cloud_source_commit": "a" * 40,
                "cloud_rollback_commit": "b" * 40,
                "website_source_commit": "c" * 40,
                "website_rollback_commit": "d" * 40,
                "image_digest": "1" * 64,
                "base_image_digest": "2" * 64,
                "schema_revision": "0071_memory_import_job_replay",
                "aws_realm_template_sha256": "3" * 64,
                "aws_recovery_template_sha256": "4" * 64,
            },
            "ingress": {
                "website_origin": "https://www.utopiahomes.com",
                "website_api_path": "/api/lucy",
                "public_service": "lucy-public",
                "model_service": "lucy-public-model",
                "model_service_private_only": True,
                "trust_forwarded_host": False,
                "max_browser_request_bytes": 8_192,
                "max_model_request_bytes": 200_000,
                "requests_per_ip_per_minute": 20,
                "requests_per_session_per_minute": 30,
            },
            "authority": {
                "node_id": node_id,
                "channel_binding_id": channel_binding_id,
                "database_login": LOGIN,
            },
            "routing": {
                "provider": "openrouter",
                "model": "google/gemini-3.1-flash-lite",
                "allowed_providers": ["google-vertex"],
                "rate_version": "openrouter-2026-09-13",
                "credential_scope_reference": "render:lucy-public-model:OPENROUTER_API_KEY",
                "zero_data_retention": True,
                "data_collection": "deny",
                "allow_fallbacks": False,
                "max_prompt_usd_per_million": 0.8,
                "max_completion_usd_per_million": 4,
            },
            "cost_policy": {
                "policy_id": "9fe8b503-78de-4ac3-8fac-36ca048152ea",
                "version": 1,
                "effective_at": datetime.now(UTC),
                "kill_state": "enabled",
                "platform_daily_cap_microusd": 10_000_000,
                "node_daily_cap_microusd": 1_000_000,
                "site_daily_cap_microusd": 1_000_000,
                "provider_daily_cap_microusd": 1_000_000,
                "outstanding_cap_microusd": 90_000,
                "per_attempt_cap_microusd": 30_000,
                "per_conversation_cap_microusd": 45_000,
                "concurrency_limit": 2,
                "requests_per_minute": 60,
                "session_requests_per_minute": 30,
                "ip_requests_per_minute": 20,
            },
            "execution": {
                "generator_max_microusd": 30_000,
                "verifier_max_microusd": 15_000,
                "generator_max_output_tokens": 700,
                "verifier_max_output_tokens": 300,
                "max_input_tokens": 20_000,
                "provider_timeout_seconds": 6,
                "public_to_model_timeout_seconds": 15,
                "website_to_public_timeout_seconds": 18,
            },
            "history": {
                "storage": "browser-memory-only",
                "max_turns": 6,
                "max_characters": 4_000,
                "expires_after_seconds": 1_800,
                "clears_on_refresh": True,
                "clears_on_close": True,
                "prior_messages_are_evidence": False,
            },
            "publication": {
                "active_snapshot_sha256": "5" * 64,
                "rollback_snapshot_sha256": "6" * 64,
                "model_allowed_snapshot_sha256": ["5" * 64],
                "withdrawn_snapshot_sha256": [],
                "source_lineage": ["synthetic-public-knowledge"],
            },
            "model_traffic_enabled": False,
            "transcript_capture_enabled": False,
            "permitted_data_classes": [
                "approved-public-knowledge",
                "temporary-browser-conversation-context",
            ],
            "permitted_actions": ["public-read-only-model-answer"],
            "operations_contact": "synthetic@example.com",
            "rollback_owner": "synthetic@example.com",
        }
    )


class _SyntheticTlsConnection:
    """Keep all SQL real while substituting the Docker fixture's absent TLS bit."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self._connection = connection

    def __enter__(self) -> _SyntheticTlsConnection:
        self._connection.__enter__()
        return self

    def __exit__(self, *args: object) -> object:
        return self._connection.__exit__(*args)

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def execute(self, query: object, params: object = None) -> object:
        if isinstance(query, str):
            query = query.replace(
                "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())",
                "true",
            )
        return self._connection.execute(query, params)  # type: ignore[arg-type]


def test_commissioning_creates_only_realm_cost_identity_and_exact_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert APP_URL is not None and OWNER_URL is not None
    owner = create_engine(OWNER_URL)
    with owner.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.restored_cost_exposures_v1,"
                "lucy.restored_cost_admission_v1,lucy.cost_events_v1,"
                "lucy.cost_recovery_outbox_v1,lucy.exposure_reservations_v1,"
                "lucy.provider_attempts_v1,lucy.provider_cost_policies_v1,"
                "lucy.public_projection_events,lucy.public_projection_routes,"
                "lucy.public_projection_versions,lucy.public_projection_approvals,"
                "lucy.public_projection_candidates,lucy.lucy_instances,"
                "lucy.node_memberships,lucy.channel_bindings,lucy.wallet_registrations,"
                "lucy.workspaces,lucy.realm_bindings,lucy.node_tenures,"
                "lucy.security_realms,lucy.nodes,lucy.tenant_accounts,"
                "lucy.principals CASCADE"
            )
        )
        if connection.scalar(
            text("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=:login)"),
            {"login": LOGIN},
        ):
            connection.execute(text(f"DROP OWNED BY {LOGIN}"))
        connection.execute(text(f"DROP ROLE IF EXISTS {LOGIN}"))
        connection.execute(text("ALTER ROLE lucy_cost_admission NOLOGIN"))
        connection.execute(
            text(
                "ALTER ROLE lucy_migration LOGIN SUPERUSER CREATEROLE "
                "PASSWORD 'synthetic-migration-only'"
            )
        )
        connection.execute(
            text(
                "UPDATE lucy.runtime_admission SET state='ready',"
                "storage_epoch=gen_random_uuid() WHERE singleton"
            )
        )
        connection.execute(text("UPDATE lucy.lifecycle SET state='ready' WHERE singleton"))
    foundation = TenancyService(create_session_factory(APP_URL)).create_node_foundation(
        account_slug="utopia-model-commissioning",
        account_name="Synthetic Utopia",
        node_slug="utopia-model-commissioning",
        node_name="Synthetic Utopia",
        node_kind="organization",
        realm_slug="utopia-model-commissioning",
        workspace_slug="website",
        hostname="www.utopiahomes.com",
    )
    manifest = _manifest(foundation.node_id, foundation.channel_binding_id)
    target = make_url(OWNER_URL)
    migration_url = target.set(
        username="lucy_migration", password="synthetic-migration-only"
    )
    model_url = target.set(username=LOGIN, password="synthetic-model-only")
    config = PublicModelCommissioningConfig(
        migration_url=migration_url,
        model_url=model_url,
        manifest=manifest,
    )
    real_connect = commissioning.psycopg.connect
    monkeypatch.setattr(
        commissioning.psycopg,
        "connect",
        lambda *args, **kwargs: _SyntheticTlsConnection(
            real_connect(*args, **kwargs)
        ),
    )
    try:
        first = commission(config)
        assert first["status"] == "passed"
        assert first["login_created"] is True
        assert first["policy_created"] is True
        assert first["provider_called"] is False
        replay = commission(config)
        assert replay["login_created"] is False
        assert replay["policy_created"] is False

        with real_connect(_conninfo(model_url)) as connection:
            assert connection.execute("SELECT session_user").fetchone() == (LOGIN,)
            assert connection.execute(
                "SELECT has_function_privilege(session_user,"
                "'lucy.reserve_provider_attempt_v1(uuid,text,uuid,uuid,text,text,text,"
                "text,text,text,bigint,integer,integer,integer,integer,timestamptz)',"
                "'EXECUTE')"
            ).fetchone() == (True,)
            assert connection.execute(
                "SELECT has_table_privilege(session_user,"
                "'lucy.provider_cost_policies_v1','SELECT')"
            ).fetchone() == (False,)
    finally:
        with owner.begin() as connection:
            if connection.scalar(
                text("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=:login)"),
                {"login": LOGIN},
            ):
                connection.execute(text(f"DROP OWNED BY {LOGIN}"))
            connection.execute(text(f"DROP ROLE IF EXISTS {LOGIN}"))
            connection.execute(text("ALTER ROLE lucy_cost_admission LOGIN"))
            connection.execute(
                text(
                    "ALTER ROLE lucy_migration NOLOGIN NOSUPERUSER NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS"
                )
            )
        owner.dispose()
