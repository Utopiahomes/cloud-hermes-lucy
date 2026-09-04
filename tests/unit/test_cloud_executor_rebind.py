from __future__ import annotations

import pytest

from deploy.postgres.rebind_executors_cloud_v1_2 import (
    AUTHORIZATION,
    RebindConfig,
    RebindError,
)


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_EXECUTOR_REBIND_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_AWS_ACCOUNT_ID": "123456789012",
        "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:123456789012:function:retrieval:production"
        ),
        "LUCY_DELETION_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:123456789012:function:deletion:production"
        ),
        "LUCY_RETRIEVAL_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        ),
        "LUCY_DELETION_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:123456789012:key/bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
        ),
        "LUCY_EXPECTED_RETRIEVAL_EXECUTOR_VERSION": "2",
        "LUCY_EXPECTED_DELETION_EXECUTOR_VERSION": "2",
        "LUCY_RETRIEVAL_EXECUTOR_VERSION": "3",
        "LUCY_DELETION_EXECUTOR_VERSION": "3",
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_SECURITY_REGISTRY_EPOCH": "1",
        "LUCY_SECURITY_KEY_EPOCH": "1",
    }


def test_rebind_configuration_accepts_only_private_quarantined_render() -> None:
    config = RebindConfig.from_environment(_environment())

    assert config.migration_url.username == "lucy_migration"
    assert config.retrieval_version == 3
    assert config.expected_retrieval_version == 2


@pytest.mark.parametrize(
    ("name", "value", "diagnostic"),
    [
        ("RENDER", "false", "private-network"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true", "capture"),
        ("LUCY_EXECUTOR_REBIND_AUTHORIZATION", "wrong", "authorization"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:secret@example.com/lucy_6tns",
            "private Render",
        ),
        ("LUCY_RETRIEVAL_EXECUTOR_VERSION", "2", "monotonically"),
    ],
)
def test_rebind_configuration_rejects_unsafe_inputs(
    name: str, value: str, diagnostic: str
) -> None:
    environment = _environment()
    environment[name] = value

    with pytest.raises(RebindError, match=diagnostic):
        RebindConfig.from_environment(environment)
