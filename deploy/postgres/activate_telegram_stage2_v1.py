"""Open one quarantined realm for approved private Telegram Stage 2.

Run only as a temporary Render migration job.  The job itself keeps capture
disabled; it verifies the reviewed Stage 2 activation manifest, an accepted
additive schema, realm bindings, capture-safe storage, and stopped runtime
identities before reopening admission.  Encrypted capture begins only after
the routine and sole gateway are separately started with their Stage 2
configuration.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from typing import Any

import psycopg
from pydantic import ValidationError

from deploy.postgres import commission_realm_runtime_v1_3 as commission
from lucy.readiness import ADMISSION_LOCK, WORKSPACES_SCHEMA_REVISION
from lucy.telegram_activation import TelegramStage2ActivationManifest

AUTHORIZATION = "telegram-stage2-activate-v1"
TARGET_REVISION = "0054_stage2_scoped_turn_commit"
ACCEPTED_REVISIONS = {TARGET_REVISION, WORKSPACES_SCHEMA_REVISION}


class Stage2ActivationError(RuntimeError):
    """The production Stage 2 activation boundary was not satisfied."""


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise Stage2ActivationError(f"missing required configuration: {name}")
    return value


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[commission.CommissionConfig, TelegramStage2ActivationManifest]:
    values = os.environ if environment is None else environment
    if values.get("LUCY_STAGE2_ACTIVATION_AUTHORIZATION") != AUTHORIZATION:
        raise Stage2ActivationError("the exact Stage 2 activation authorization is required")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise Stage2ActivationError("the activation job must keep capture disabled")
    raw_manifest = _required(values, "LUCY_STAGE2_ACTIVATION_MANIFEST_JSON")
    digest = hashlib.sha256(raw_manifest.encode("utf-8")).hexdigest()
    if digest != _required(values, "LUCY_STAGE2_ACTIVATION_MANIFEST_SHA256"):
        raise Stage2ActivationError("Stage 2 activation manifest digest differs")
    try:
        manifest = TelegramStage2ActivationManifest.model_validate_json(raw_manifest)
        config = commission.CommissionConfig.from_environment("open", values)
    except (ValidationError, commission.CommissionError) as exc:
        raise Stage2ActivationError("Stage 2 activation configuration is invalid") from exc
    stamp = config.stamp
    if stamp is None or config.runtime_epoch is None:
        raise Stage2ActivationError("realm activation material is incomplete")
    if (
        manifest.realm.node_id != stamp.node_id
        or manifest.realm.security_realm_id != stamp.security_realm_id
        or manifest.realm.content_scope_id != stamp.content_scope_id
        or manifest.realm.routine_render_service_id == manifest.realm.gateway_render_service_id
    ):
        raise Stage2ActivationError("Stage 2 manifest does not match the reviewed realm")
    return config, manifest


def _scalar(connection: psycopg.Connection[Any], query: str) -> Any:
    row = connection.execute(query).fetchone()
    if row is None:
        raise Stage2ActivationError("Stage 2 verification query returned no row")
    return row[0]


def activate(
    config: commission.CommissionConfig,
    manifest: TelegramStage2ActivationManifest,
) -> dict[str, object]:
    with psycopg.connect(commission._conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute(
            "SELECT pg_advisory_xact_lock(%s)", (commission.MAINTENANCE_LOCK,)
        )
        connection.execute(
            "SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,)
        )
        state, epoch = commission._verify_target_boundary(connection)
        schema_revision = str(
            _scalar(connection, "SELECT version_num FROM public.alembic_version")
        )
        if schema_revision not in ACCEPTED_REVISIONS:
            raise Stage2ActivationError("database is not at an accepted Stage 2 revision")
        blockers = commission._capture_blockers(connection, config)
        commission._verify_open_boundary(connection, config, blockers)
        pending = commission._work_in_flight(connection, config)
        sessions = commission._runtime_sessions(connection, config)
        finality_pending = commission._finality_pending(connection, config)
        if pending:
            raise Stage2ActivationError("realm has unresolved sensitive authority")
        if sessions:
            raise Stage2ActivationError("realm runtime sessions must be stopped before activation")
        replayed = state == "ready" and epoch == config.runtime_epoch
        if not replayed:
            if state != "quarantined":
                raise Stage2ActivationError("storage admission is not quarantined")
            connection.execute(
                "UPDATE lucy.runtime_admission SET state='ready',storage_epoch=%s,"
                "updated_at=now() WHERE singleton",
                (config.runtime_epoch,),
            )
        return {
            "contract": "lucy.telegram.private.stage2.activation-receipt.v1",
            "status": "passed",
            "schema_revision": schema_revision,
            "runtime_admission": "ready",
            "runtime_epoch_present": True,
            "capture_enabled": False,
            "capture_activation_authorized": manifest.transcript_capture_enabled,
            "unresolved_sensitive_authority": pending,
            "finality_pending": finality_pending,
            "runtime_sessions": sessions,
            "replayed": replayed,
        }


def main() -> int:
    try:
        config, manifest = configuration_from_environment()
        report = activate(config, manifest)
    except Stage2ActivationError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.telegram.private.stage2.activation-receipt.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.telegram.private.stage2.activation-receipt.v1",
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
