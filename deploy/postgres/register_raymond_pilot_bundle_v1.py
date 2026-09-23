"""Register one exact, locally preflighted Raymond pilot from a temporary Render job.

The authorization is plaintext-free and delivered in bounded compressed parts. This
command never reads conversation text, enables capture, or calls a model provider.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
from datetime import UTC, datetime

import psycopg
from sqlalchemy.engine import make_url

from lucy.chatgpt_manifest import AuthorizedPilotManifestV1
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_import_cli import PilotExecutionPreflightV1

AUTHORIZATION = "register-raymond-approved-early-pilot-v1"
DIGEST = "15b2d1f70e50920d4605862d5c6772a8e28b24003681b5101671648813312b24"
SCOPE = "5ee9fc67-4c46-4416-876e-5e028bf8ae4e"
HOST = "dpg-dak5bqad0e5s73b2e3d0-a"


def _decode_authorization() -> bytes:
    count = int(os.environ.get("LUCY_PILOT_AUTH_PART_COUNT", "0"))
    if not 1 <= count <= 8:
        raise RuntimeError("pilot authorization part count is invalid")
    chunks = [os.environ[f"LUCY_PILOT_AUTH_PART_{index}"] for index in range(count)]
    if any(not 1 <= len(chunk) <= 32_000 for chunk in chunks):
        raise RuntimeError("pilot authorization part size is invalid")
    encoded = "".join(chunks)
    if len(encoded) > 128_000:
        raise RuntimeError("pilot authorization exceeds the compressed ceiling")
    compressed = base64.b64decode(encoded, validate=True)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(1_000_001)
    if len(raw) > 1_000_000:
        raise RuntimeError("pilot authorization exceeds the raw ceiling")
    if hashlib.sha256(raw).hexdigest() != os.environ.get("LUCY_PILOT_AUTH_SHA256"):
        raise RuntimeError("pilot authorization transfer commitment differs")
    return raw


def main() -> int:
    if (
        os.getenv("RENDER") != "true"
        or os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or os.getenv("LUCY_RAYMOND_PILOT_REGISTRATION_AUTHORIZATION") != AUTHORIZATION
    ):
        raise RuntimeError("Raymond pilot registration environment is not authorized")
    parsed = make_url(os.environ["LUCY_MIGRATION_DATABASE_URL"])
    if (
        parsed.host != HOST or parsed.database != "lucy_raymond"
        or parsed.username != "lucy_migration" or not parsed.password
        or parsed.query.get("sslmode") != "require"
    ):
        raise RuntimeError("Raymond pilot registration database boundary changed")
    authorization = AuthorizedPilotManifestV1.model_validate_json(_decode_authorization())
    preflight = PilotExecutionPreflightV1.model_validate_json(
        base64.b64decode(os.environ["LUCY_PILOT_PREFLIGHT_B64"], validate=True)
    )
    now = datetime.now(UTC)
    manifest = authorization.bundle.manifest
    if not (
        authorization.bundle_digest == preflight.bundle_digest == DIGEST
        and str(authorization.bundle.destination_content_scope_id) == SCOPE
        and str(preflight.destination_content_scope_id) == SCOPE
        and authorization.bundle.included_record_count == preflight.included_record_count == 474
        and manifest.max_model_spend_microusd == preflight.maximum_model_spend_microusd == 2_000_000
        and manifest.max_attempts == preflight.maximum_attempts == 20
        and manifest.model_route == "google/gemini-3.1-flash-lite"
        and manifest.provider_policy_id == "openrouter-zdr-deny-no-fallback-validated-json-v1"
        and preflight.owner_approval_ref == authorization.owner_approval_ref
        and preflight.campaign_id == authorization.bundle.campaign_id
        and authorization.approved_at <= preflight.checked_at <= now
        and now < preflight.expires_at == manifest.expires_at
        and (now - preflight.checked_at).total_seconds() <= 900
        and preflight.ready_for_execution and preflight.network_calls == 0
    ):
        raise RuntimeError("Raymond pilot registration is not exact or fresh")
    dsn = parsed.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(dsn) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        admission = connection.execute(
            "SELECT state FROM lucy.runtime_admission WHERE singleton"
        ).fetchone()
        if admission != ("quarantined",):
            raise RuntimeError("Raymond admission must be quarantined for registration")
        revision = connection.execute(
            "SELECT version_num FROM public.alembic_version"
        ).fetchone()
        if revision != ("0073_memory_candidate_correction",):
            raise RuntimeError("Raymond schema revision changed")
        result = connection.execute(
            "SELECT lucy.register_memory_import_pilot_authorization_v1(%s::jsonb)",
            (canonical_json_bytes(authorization).decode("utf-8"),),
        ).fetchone()
        if (
            result is None
            or result[0].get("owner_approval_ref") != str(authorization.owner_approval_ref)
        ):
            raise RuntimeError("Raymond pilot registration acknowledgement changed")
    print(json.dumps({"contract": "lucy.raymond-pilot-registration.v1", "status": "passed",
                      "bundle_digest": DIGEST, "included_record_count": 474,
                      "provider_calls": 0, "archive_calls": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
