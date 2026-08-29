from __future__ import annotations

import pytest

from lucy.secret_filter import MemorySecretDetected, reject_memory_secrets


@pytest.mark.parametrize(
    "value",
    [
        "api_key = sk-abcdefghijklmnopqrstuvwxyz012345",
        "password: correct-horse-battery-staple",
        "AWS credential AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN PRIVATE KEY-----",
        "bot token 1234567890:abcdefghijklmnopqrstuvwxyzABCDEFGHIJK",
    ],
)
def test_high_confidence_credentials_are_rejected(value: str) -> None:
    with pytest.raises(MemorySecretDetected):
        reject_memory_secrets(value)


def test_normal_preferences_are_not_misclassified() -> None:
    reject_memory_secrets(
        "Forti",
        "prefers",
        "Lucy should remember conversations unless explicitly off the record",
    )
