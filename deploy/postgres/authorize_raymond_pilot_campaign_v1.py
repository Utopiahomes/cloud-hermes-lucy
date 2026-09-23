"""Authorize Ray's exact early pilot campaign under the isolated policy login."""

from __future__ import annotations

import json
import os

from sqlalchemy.engine import make_url

from deploy.postgres.register_raymond_pilot_bundle_v1 import (
    DIGEST,
    SCOPE,
    _decode_authorization,
)
from lucy.chatgpt_manifest import AuthorizedPilotManifestV1
from lucy.db import create_session_factory
from lucy.governed_memory import GovernedMemoryPolicy

AUTHORIZATION = "authorize-raymond-approved-early-campaign-v1"
HOST = "dpg-dak5bqad0e5s73b2e3d0-a"


def main() -> int:
    if (
        os.getenv("RENDER") != "true"
        or os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or os.getenv("LUCY_RAYMOND_CAMPAIGN_AUTHORIZATION") != AUTHORIZATION
    ):
        raise RuntimeError("Raymond campaign authorization environment is invalid")
    url = make_url(os.environ["LUCY_DATABASE_URL"])
    if (
        url.host != HOST or url.database != "lucy_raymond"
        or url.username != "lucy_raymond_policy" or not url.password
        or url.query.get("sslmode") != "require"
    ):
        raise RuntimeError("Raymond policy database boundary changed")
    approved = AuthorizedPilotManifestV1.model_validate_json(_decode_authorization())
    manifest = approved.bundle.manifest
    if not (
        approved.bundle_digest == DIGEST
        and str(approved.bundle.destination_content_scope_id) == SCOPE
        and approved.bundle.included_record_count == 474
        and manifest.max_model_spend_microusd == 2_000_000
        and manifest.max_attempts == 20
        and manifest.model_route == "google/gemini-3.1-flash-lite"
    ):
        raise RuntimeError("Raymond early campaign differs from approved bounds")
    result = GovernedMemoryPolicy(
        create_session_factory(url.render_as_string(hide_password=False))
    ).authorize_campaign(manifest)
    if result.campaign_id != manifest.campaign_id:
        raise RuntimeError("Raymond policy campaign acknowledgement changed")
    print(json.dumps({
        "contract": "lucy.raymond-early-campaign.v1", "status": "passed",
        "campaign_id": str(result.campaign_id), "bundle_digest": DIGEST,
        "provider_calls": 0, "archive_calls": 0,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
