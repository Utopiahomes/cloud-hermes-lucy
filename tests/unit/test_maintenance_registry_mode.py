from __future__ import annotations

from uuid import uuid4

import pytest

from lucy.maintenance import (
    _require_executor_bound_registry_environment,
    _verify_archive_registry_refs,
)
from lucy.readiness import ReadinessError


class _KeyStore:
    def __init__(self, value: object | None = None) -> None:
        self.value = value
        self.get_calls = 0

    def get(self, _key_ref: object) -> object | None:
        self.get_calls += 1
        return self.value


def _environment() -> dict[str, str]:
    return {
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_ENVIRONMENT": "production",
        "LUCY_SERVICE_MODE": "routine",
        "LUCY_ARCHIVE_BACKEND": "aws-kms-dynamodb",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
    }


def test_executor_bound_mode_requires_the_exact_production_boundary() -> None:
    _require_executor_bound_registry_environment(_environment())
    for key, value in {
        "LUCY_ENVIRONMENT": "development",
        "LUCY_SECURITY_ENVIRONMENT": "test",
        "LUCY_SERVICE_MODE": "evidence",
        "LUCY_ARCHIVE_BACKEND": "local",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
    }.items():
        with pytest.raises(ReadinessError):
            _require_executor_bound_registry_environment(_environment() | {key: value})


def test_executor_bound_mode_does_not_grant_or_attempt_registry_reads() -> None:
    store = _KeyStore()
    _verify_archive_registry_refs(
        [uuid4()],
        store,  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        executor_bound=True,
    )
    assert store.get_calls == 0


def test_direct_registry_mode_still_fails_on_a_missing_wrapped_key() -> None:
    store = _KeyStore()
    with pytest.raises(ReadinessError, match="archive registry mismatch"):
        _verify_archive_registry_refs(
            [uuid4()],
            store,  # type: ignore[arg-type]
            None,
            executor_bound=False,
        )
    assert store.get_calls == 1


def test_executor_bound_mode_requires_both_identity_objects() -> None:
    for store, journal in ((None, object()), (_KeyStore(), None)):
        with pytest.raises(ReadinessError, match="archive and journal identities"):
            _verify_archive_registry_refs(
                [uuid4()],
                store,  # type: ignore[arg-type]
                journal,  # type: ignore[arg-type]
                executor_bound=True,
            )
