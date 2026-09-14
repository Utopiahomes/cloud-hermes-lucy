from __future__ import annotations

import pytest

from deploy.postgres.bootstrap_realm_cloud_v1_3 import AUTHORIZATION, BootstrapError
from deploy.postgres.commission_telegram_stage1_v1 import configuration_from_environment


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_REALM_BOOTSTRAP_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@dpg-example-a/lucy",
        "LUCY_TELEGRAM_NODE_ID": "5fdadf90-7273-49c1-9e61-c4bc99e4b342",
        "LUCY_TELEGRAM_TENURE_ID": "2bbd6a40-e619-42ea-8ecb-6b8bcd27cd02",
        "LUCY_TELEGRAM_REALM_ID": "ac501621-280d-46ff-a065-f65a0566a839",
        "LUCY_TELEGRAM_WORKSPACE_ID": "e57e7270-77d7-4734-b5d2-e6ecfb6509d5",
        "TELEGRAM_ALLOWED_USERS": "1234567",
        "LUCY_TELEGRAM_BOT_ID": "7654321",
        "LUCY_AUTHORITY_STREAM_ID": "3b42f756-f48a-47fe-bd13-b7b45be913ee",
        "LUCY_AUTHORITY_EPOCH": "1",
        "LUCY_AUTHORITY_WRITER_URL": "http://lucy-authority-writer:10000",
        "LUCY_AUTHORITY_WRITER_TOKEN": "synthetic-writer-token",
        "LUCY_AUTHORITY_ACK_URL": "http://lucy-recovery-coordinator:10000",
        "LUCY_AUTHORITY_ACK_TOKEN": "synthetic-ack-token",
        "LUCY_TELEGRAM_ACTIVATION_DECISION_ID": "owner-approved:telegram-stage1-2026-09-11",
    }


def test_configuration_derives_stable_content_free_binding() -> None:
    first = configuration_from_environment(_environment())
    second = configuration_from_environment(_environment())
    assert first.channel_binding_id == second.channel_binding_id
    assert first.binding_digest == second.binding_digest
    assert len(first.binding_digest) == 64


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_TELEGRAM_BOT_ID", "0"),
        ("TELEGRAM_ALLOWED_USERS", "not-numeric"),
        ("LUCY_AUTHORITY_EPOCH", "0"),
        ("LUCY_AUTHORITY_WRITER_URL", "https://example.com"),
        ("LUCY_TELEGRAM_ACTIVATION_DECISION_ID", "contains whitespace"),
    ],
)
def test_configuration_rejects_changed_boundary(key: str, value: str) -> None:
    with pytest.raises(BootstrapError):
        configuration_from_environment(_environment() | {key: value})
