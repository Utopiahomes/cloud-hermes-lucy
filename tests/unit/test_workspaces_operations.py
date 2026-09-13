from uuid import UUID

import pytest

from lucy.publication import PublicAnswer
from lucy.workspaces_operations import (
    ApprovedProjectionWorkspacesOperations,
    WorkspacesOperationUnavailable,
)

ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")


class Reader:
    def __init__(self, digest: str = "a" * 64) -> None:
        self.digest = digest

    def answer_admitted(self, **values: object) -> PublicAnswer:
        assert values == {
            "hostname": "www.utopiahomes.com",
            "question": "What homes are available?",
            "storage_epoch": ONE,
        }
        return PublicAnswer("Shamrock House is available.", "approved-faq", 3, self.digest)


class Tasks:
    def delegate(self, **values: object) -> UUID:
        assert values["request_id"] == ONE
        assert values["instruction"] == "Draft a viewing plan"
        return TWO


def _operations(reader: Reader, tasks: Tasks | None = None):
    return ApprovedProjectionWorkspacesOperations(
        reader=reader,  # type: ignore[arg-type]
        hostname="www.utopiahomes.com",
        storage_epoch=ONE,
        snapshot_digest="a" * 64,
        task_delegator=tasks,  # type: ignore[arg-type]
    )


def test_knowledge_reads_only_the_pinned_approved_snapshot() -> None:
    result = _operations(Reader()).query_knowledge(
        context=object(),  # type: ignore[arg-type]
        question="What homes are available?",
    )
    assert result == ("Shamrock House is available.", "approved-faq", 3, "a" * 64)


def test_snapshot_digest_mismatch_fails_closed() -> None:
    with pytest.raises(WorkspacesOperationUnavailable):
        _operations(Reader("b" * 64)).query_knowledge(
            context=object(),  # type: ignore[arg-type]
            question="What homes are available?",
        )


def test_task_delegation_requires_an_injected_queue() -> None:
    with pytest.raises(WorkspacesOperationUnavailable):
        _operations(Reader()).delegate_task(
            context=object(),  # type: ignore[arg-type]
            request_id=ONE,
            instruction="Draft a viewing plan",
        )
    assert (
        _operations(Reader(), Tasks()).delegate_task(
            context=object(),  # type: ignore[arg-type]
            request_id=ONE,
            instruction="Draft a viewing plan",
        )
        == TWO
    )
