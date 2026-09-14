"""Commission and durably activate one private Telegram Stage 1 binding.

Run only as a temporary Render job on the private network. The job holds the
migration connection and the two narrow recovery API tokens, but no AWS role or
Telegram/OpenRouter secret. Repeated execution is idempotent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg
from sqlalchemy.engine import URL

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    _LUCY_DATABASE,
    _PRIVATE_RENDER_HOST,
    AUTHORIZATION,
    EXPECTED_REVISION,
    BootstrapError,
    _conninfo,
    _database_url,
)

_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+=-]*\Z")
_PRIVATE_URL = re.compile(r"http://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:[0-9]{2,5}\Z")


@dataclass(frozen=True)
class Configuration:
    migration_url: URL
    node_id: UUID
    tenure_id: UUID
    realm_id: UUID
    workspace_id: UUID
    owner_user_id: int
    bot_id: int
    authority_stream_id: UUID
    authority_epoch: int
    authority_writer_url: str
    authority_writer_token: str
    authority_ack_url: str
    authority_ack_token: str
    decision_id: str

    @property
    def principal_id(self) -> UUID:
        return uuid5(NAMESPACE_URL, f"lucy:utopia:telegram-owner:{self.owner_user_id}")

    @property
    def membership_id(self) -> UUID:
        return uuid5(NAMESPACE_URL, f"lucy:utopia:telegram-membership:{self.owner_user_id}")

    @property
    def channel_binding_id(self) -> UUID:
        return uuid5(NAMESPACE_URL, f"lucy:utopia:telegram-private:{self.bot_id}")

    @property
    def binding_digest(self) -> str:
        value = {
            "bot_id": self.bot_id,
            "channel_binding_id": str(self.channel_binding_id),
            "node_id": str(self.node_id),
            "owner_user_id": self.owner_user_id,
            "realm_id": str(self.realm_id),
            "workspace_id": str(self.workspace_id),
        }
        canonical = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(canonical).hexdigest()


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise BootstrapError(f"missing required configuration: {name}")
    return value


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> Configuration:
    values = os.environ if environment is None else environment
    if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
        raise BootstrapError("Telegram commissioning requires production Render")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise BootstrapError("transcript capture must remain disabled")
    if values.get("LUCY_REALM_BOOTSTRAP_AUTHORIZATION") != AUTHORIZATION:
        raise BootstrapError("the exact reviewed commissioning authorization is required")
    migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
    if (
        migration_url.username != "lucy_migration"
        or migration_url.host is None
        or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
        or migration_url.database is None
        or _LUCY_DATABASE.fullmatch(migration_url.database) is None
        or migration_url.port not in (None, 5432)
    ):
        raise BootstrapError("Telegram commissioning database boundary differs")
    writer_url = _required(values, "LUCY_AUTHORITY_WRITER_URL").rstrip("/")
    ack_url = _required(values, "LUCY_AUTHORITY_ACK_URL").rstrip("/")
    if _PRIVATE_URL.fullmatch(writer_url) is None or _PRIVATE_URL.fullmatch(ack_url) is None:
        raise BootstrapError("recovery services must use private Render URLs")
    decision_id = _required(values, "LUCY_TELEGRAM_ACTIVATION_DECISION_ID")
    if _SAFE.fullmatch(decision_id) is None:
        raise BootstrapError("activation decision identifier is invalid")
    try:
        config = Configuration(
            migration_url=migration_url,
            node_id=UUID(_required(values, "LUCY_TELEGRAM_NODE_ID")),
            tenure_id=UUID(_required(values, "LUCY_TELEGRAM_TENURE_ID")),
            realm_id=UUID(_required(values, "LUCY_TELEGRAM_REALM_ID")),
            workspace_id=UUID(_required(values, "LUCY_TELEGRAM_WORKSPACE_ID")),
            owner_user_id=int(_required(values, "TELEGRAM_ALLOWED_USERS")),
            bot_id=int(_required(values, "LUCY_TELEGRAM_BOT_ID")),
            authority_stream_id=UUID(_required(values, "LUCY_AUTHORITY_STREAM_ID")),
            authority_epoch=int(_required(values, "LUCY_AUTHORITY_EPOCH")),
            authority_writer_url=writer_url,
            authority_writer_token=_required(values, "LUCY_AUTHORITY_WRITER_TOKEN"),
            authority_ack_url=ack_url,
            authority_ack_token=_required(values, "LUCY_AUTHORITY_ACK_TOKEN"),
            decision_id=decision_id,
        )
    except (TypeError, ValueError) as exc:
        raise BootstrapError("Telegram commissioning identifiers are invalid") from exc
    if config.owner_user_id <= 0 or config.bot_id <= 0 or config.authority_epoch < 1:
        raise BootstrapError("Telegram commissioning numeric identifiers are invalid")
    return config


def _post(url: str, token: str) -> dict[str, Any]:
    request = Request(url, data=b"", method="POST", headers={"Authorization": f"Bearer {token}"})
    with urlopen(request, timeout=20) as response:  # noqa: S310 - validated private Render URL
        value: dict[str, Any] = json.load(response)
    return value


def _provision_and_stage(config: Configuration) -> tuple[UUID, bool]:
    now = datetime.now(UTC)
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='10s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (0x4C5543594144,))
        boundary = connection.execute(
            "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "EXISTS(SELECT 1 FROM lucy.nodes WHERE id=%s),"
            "EXISTS(SELECT 1 FROM lucy.node_tenures WHERE id=%s AND node_id=%s "
            "AND ends_at IS NULL),"
            "EXISTS(SELECT 1 FROM lucy.realm_bindings WHERE tenure_id=%s AND realm_id=%s "
            "AND valid_to IS NULL),"
            "EXISTS(SELECT 1 FROM lucy.workspaces WHERE id=%s AND node_id=%s AND tenure_id=%s)",
            (
                config.node_id,
                config.tenure_id,
                config.node_id,
                config.tenure_id,
                config.realm_id,
                config.workspace_id,
                config.node_id,
                config.tenure_id,
            ),
        ).fetchone()
        expected_boundary = (
            "lucy_migration",
            EXPECTED_REVISION,
            "quarantined",
            True,
            True,
            True,
            True,
            True,
        )
        if boundary != expected_boundary:
            raise BootstrapError("Telegram commissioning scope or quarantine boundary differs")
        connection.execute(
            "INSERT INTO lucy.principals(id,issuer,subject,principal_kind,display_name,created_at) "
            "VALUES(%s,'telegram',%s,'human','Utopia owner',%s) ON CONFLICT DO NOTHING",
            (config.principal_id, str(config.owner_user_id), now),
        )
        connection.execute(
            "INSERT INTO lucy.node_memberships("
            "id,principal_id,workspace_id,role,status,granted_at) "
            "VALUES(%s,%s,%s,'owner','active',%s) ON CONFLICT DO NOTHING",
            (config.membership_id, config.principal_id, config.workspace_id, now),
        )
        connection.execute(
            "INSERT INTO lucy.channel_bindings(id,hostname,node_id,tenure_id,workspace_id,"
            "channel_kind,active,created_at) VALUES(%s,'telegram.private.utopia.internal',"
            "%s,%s,%s,'internal',false,%s) ON CONFLICT DO NOTHING",
            (config.channel_binding_id, config.node_id, config.tenure_id, config.workspace_id, now),
        )
        connection.execute(
            "INSERT INTO lucy.telegram_channel_bindings_v1(channel_binding_id,bot_id,"
            "owner_user_id,binding_digest,created_at) VALUES(%s,%s,%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            (
                config.channel_binding_id,
                config.bot_id,
                config.owner_user_id,
                config.binding_digest,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO lucy.telegram_budget_accounts_v1(security_realm_id,daily_limit_microusd,"
            "period_date,reserved_microusd,spent_microusd,updated_at) "
            "VALUES(%s,1000000,current_date,0,0,%s) ON CONFLICT DO NOTHING",
            (config.realm_id, now),
        )
        exact = connection.execute(
            "SELECT p.issuer,p.subject,p.status,m.role,m.status,c.active,c.generation,"
            "tb.bot_id,tb.owner_user_id,tb.binding_digest,b.daily_limit_microusd "
            "FROM lucy.principals p JOIN lucy.node_memberships m ON m.principal_id=p.id "
            "JOIN lucy.channel_bindings c ON c.workspace_id=m.workspace_id "
            "JOIN lucy.telegram_channel_bindings_v1 tb ON tb.channel_binding_id=c.id "
            "JOIN lucy.telegram_budget_accounts_v1 b ON b.security_realm_id=%s "
            "WHERE p.id=%s AND m.id=%s AND c.id=%s",
            (config.realm_id, config.principal_id, config.membership_id, config.channel_binding_id),
        ).fetchone()
        expected_prefix = (
            "telegram",
            str(config.owner_user_id),
            "active",
            "owner",
            "active",
        )
        expected_suffix = (
            config.bot_id,
            config.owner_user_id,
            config.binding_digest,
            1000000,
        )
        if (
            exact is None
            or exact[:5] != expected_prefix
            or exact[5:7] not in ((False, 1), (True, 2))
            or exact[7:] != expected_suffix
        ):
            raise BootstrapError("existing Telegram commissioning state differs")
        connection.execute("SET LOCAL ROLE lucy_authority_function_owner")
        result = connection.execute(
            "SELECT lucy.stage_channel_activation_v1(%s,%s,%s,%s,%s,%s,%s)",
            (
                config.channel_binding_id,
                config.principal_id,
                config.authority_stream_id,
                config.authority_epoch,
                f"{config.decision_id}:activate",
                config.decision_id,
                config.binding_digest,
            ),
        ).fetchone()
        if result is None or not isinstance(result[0], dict):
            raise BootstrapError("Telegram activation staging returned no event")
        event_id = UUID(str(result[0]["event_id"]))
        already_durable = result[0].get("state") == "DURABLY_RECORDED"
    return event_id, already_durable


def commission(config: Configuration) -> dict[str, Any]:
    event_id, already_durable = _provision_and_stage(config)
    if not already_durable:
        writer: dict[str, Any] | None
        try:
            writer = _post(
                f"{config.authority_writer_url}/v1/recovery/events/{event_id}",
                config.authority_writer_token,
            )
        except HTTPError as exc:
            if exc.code != 503:
                raise
            # A crash after the independent append but before acknowledgement can
            # make a strict conditional re-append fail. Continue only to the
            # independent receiver; it proves the exact journal event exists.
            writer = None
        if writer is not None and (
            str(writer.get("event_id")) != str(event_id)
            or writer.get("stream_kind") != "authority"
        ):
            raise BootstrapError("authority journal receipt differs")
        acknowledgement = _post(
            f"{config.authority_ack_url}/v1/recovery/authority/acknowledgements/{event_id}",
            config.authority_ack_token,
        )
        if (
            str(acknowledgement.get("event_id")) != str(event_id)
            or acknowledgement.get("state") != "DURABLY_RECORDED"
        ):
            raise BootstrapError("authority acknowledgement differs")
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        verified = connection.execute(
            "SELECT c.active,c.generation,o.acknowledged_at IS NOT NULL,"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1() FROM lucy.channel_bindings c "
            "JOIN lucy.authority_recovery_outbox_v1 o ON o.event_id=%s WHERE c.id=%s",
            (event_id, config.channel_binding_id),
        ).fetchone()
    if verified != (True, 2, True, "quarantined", True):
        raise BootstrapError("durable Telegram activation verification failed")
    return {
        "contract": "lucy.telegram.private.stage1.commissioning.v1",
        "status": "passed",
        "channel_active": True,
        "generation": 2,
        "authority_durable": True,
        "admission_state": "quarantined",
        "capture_enabled": False,
    }


def main() -> None:
    print(json.dumps(commission(configuration_from_environment()), sort_keys=True))


if __name__ == "__main__":
    main()
