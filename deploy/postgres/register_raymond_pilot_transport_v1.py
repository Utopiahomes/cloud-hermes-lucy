"""Register the exact approved Raymond pilot transport commitments privately."""

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

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_pilot_transport import MemoryPilotTransportRegistrationV1

AUTHORIZATION = "register-raymond-approved-early-transport-v1"
DIGEST = "15b2d1f70e50920d4605862d5c6772a8e28b24003681b5101671648813312b24"
CAMPAIGN = "c1800ec3-1158-42f0-bb0b-46a04df7a65c"
SCOPE = "5ee9fc67-4c46-4416-876e-5e028bf8ae4e"
HOST = "dpg-dak5bqad0e5s73b2e3d0-a"


def main() -> int:
    if (
        os.getenv("RENDER") != "true"
        or os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or os.getenv("LUCY_RAYMOND_TRANSPORT_REGISTRATION_AUTHORIZATION") != AUTHORIZATION
    ):
        raise RuntimeError("Raymond transport registration environment is invalid")
    url = make_url(os.environ["LUCY_MIGRATION_DATABASE_URL"])
    if (
        url.host != HOST or url.database != "lucy_raymond"
        or url.username != "lucy_migration" or not url.password
        or url.query.get("sslmode") != "require"
    ):
        raise RuntimeError("Raymond transport database boundary changed")
    encoded = os.environ["LUCY_PILOT_TRANSPORT_GZIP_B64"]
    if not 1 <= len(encoded) <= 40_000:
        raise RuntimeError("Raymond transport transfer exceeds ceiling")
    compressed = base64.b64decode(encoded, validate=True)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(200_001)
    if len(raw) > 200_000 or hashlib.sha256(raw).hexdigest() != os.environ.get(
        "LUCY_PILOT_TRANSPORT_SHA256"
    ):
        raise RuntimeError("Raymond transport transfer commitment differs")
    plan = MemoryPilotTransportRegistrationV1.model_validate_json(raw)
    if not (
        plan.bundle_digest == DIGEST
        and str(plan.campaign_id) == CAMPAIGN
        and str(plan.destination_content_scope_id) == SCOPE
        and len(plan.batches) == 13
        and datetime.now(UTC) < plan.expires_at
    ):
        raise RuntimeError("Raymond transport registration differs from approved pilot")
    dsn = url.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(dsn) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        state = connection.execute(
            "SELECT state FROM lucy.runtime_admission WHERE singleton"
        ).fetchone()
        if state != ("quarantined",):
            raise RuntimeError("Raymond admission must be quarantined for registration")
        row = connection.execute(
            "SELECT lucy.register_memory_pilot_transport_v1(%s::jsonb)",
            (canonical_json_bytes(plan).decode("utf-8"),),
        ).fetchone()
        if row is None or row[0].get("campaign_id") != CAMPAIGN:
            raise RuntimeError("Raymond transport registration acknowledgement changed")
    print(json.dumps({"contract": "lucy.raymond-pilot-transport-registration.v1",
                      "status": "passed", "batch_count": 13, "bundle_digest": DIGEST,
                      "plaintext_uploaded": False, "provider_calls": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
