from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import SecretStr

from lucy.authenticated_memory import AuthenticatedScopedMemoryGateway
from lucy.internal_admission import InternalAdmissionDenied
from lucy.scoped_memory import (
    ScopedMemoryClaim,
    ScopedMemoryWrite,
    ScopedMemoryWriteResult,
)

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 9, 9, 15, 0, tzinfo=UTC)


class AdmissionSpy:
    def __init__(self, memory: MemorySpy, *, deny: bool = False) -> None:
        self.memory = memory
        self.deny = deny
        self.calls: list[dict[str, object]] = []

    def admit(self, **values: object) -> object:
        self.calls.append(values)
        if self.deny:
            raise InternalAdmissionDenied("internal request is not authorized")
        return object()

    def _scoped_memory_for_effect(self, *, action: str) -> MemorySpy:
        self.calls.append({"effect_action": action})
        return self.memory


class MemorySpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def write(self, candidate: ScopedMemoryWrite) -> ScopedMemoryWriteResult:
        self.calls.append(("write", candidate))
        return ScopedMemoryWriteResult(claim_id=ONE, replayed=False)

    def search(self, query: str, *, limit: int = 10) -> tuple[ScopedMemoryClaim, ...]:
        self.calls.append(("search", (query, limit)))
        return ()


def _gateway(admission: AdmissionSpy) -> AuthenticatedScopedMemoryGateway:
    return AuthenticatedScopedMemoryGateway(
        admission=admission,  # type: ignore[arg-type]
        workspace_id=ONE,
    )


def test_gateway_admits_exact_configured_workspace_before_memory_effect() -> None:
    memory = MemorySpy()
    admission = AdmissionSpy(memory)
    gateway = _gateway(admission)

    assert gateway.search(
        credential=SecretStr("identity-proof"),
        request_id=ZERO,
        query="canary",
        checked_at=NOW,
        limit=3,
    ) == ()

    call = admission.calls[0]
    assert call["action"] == "memory.read"
    assert call["resource_selector"].object_id == ONE  # type: ignore[union-attr]
    assert admission.calls[1] == {"effect_action": "memory.read"}
    assert memory.calls == [("search", ("canary", 3))]


def test_denied_admission_never_reaches_memory_effect() -> None:
    memory = MemorySpy()
    admission = AdmissionSpy(memory, deny=True)
    gateway = _gateway(admission)

    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        gateway.write(
            credential=SecretStr("identity-proof"),
            request_id=ZERO,
            candidate=ScopedMemoryWrite(
                idempotency_key="one",
                subject="Lucy",
                predicate="boundary",
                object="Utopia only",
                confidence_millionths=1_000_000,
            ),
            checked_at=NOW,
        )

    assert memory.calls == []
