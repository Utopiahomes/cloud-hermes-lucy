"""Run evidence-exact acceptance cases against a Public Lucy knowledge candidate."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from lucy.public_contracts import PublicHistoryTurn, PublicKnowledgeSnapshot
from lucy.public_retrieval import PublicKnowledgeRetriever


class AcceptanceCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    question: str = Field(min_length=2, max_length=500)
    history: tuple[PublicHistoryTurn, ...] = Field(default=(), max_length=6)
    expected_outcome: Literal["answered", "partial", "fallback"]
    expected_evidence_ids: tuple[str, ...]
    expected_missing_topics: tuple[str, ...]


class AcceptanceSuite(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.public-knowledge.acceptance.v1"]
    cases: tuple[AcceptanceCase, ...] = Field(min_length=1, max_length=100)


class AcceptanceFailure(ValueError):
    """One or more candidate-corpus expectations did not hold."""


def evaluate(candidate_path: Path, suite_path: Path) -> dict[str, object]:
    candidate = PublicKnowledgeSnapshot.model_validate_json(
        candidate_path.read_text(encoding="utf-8")
    )
    suite = AcceptanceSuite.model_validate_json(suite_path.read_text(encoding="utf-8"))
    retriever = PublicKnowledgeRetriever()
    failures: list[str] = []
    for case in suite.cases:
        result = retriever.retrieve(
            question=case.question,
            entries=candidate.entries,
            history=case.history,
            observed_at=datetime.now(UTC),
        )
        actual = (result.outcome, result.evidence_ids, result.missing_topics)
        expected = (
            case.expected_outcome,
            case.expected_evidence_ids,
            case.expected_missing_topics,
        )
        if actual != expected:
            failures.append(case.id)
    if failures:
        raise AcceptanceFailure(f"public knowledge acceptance failed: {', '.join(failures)}")
    return {
        "contract": suite.contract,
        "status": "passed",
        "cases": len(suite.cases),
        "candidate_entries": len(candidate.entries),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument(
        "--suite",
        type=Path,
        default=Path(__file__).with_name("public_knowledge_acceptance.v1.json"),
    )
    args = parser.parse_args()
    try:
        report = evaluate(args.candidate, args.suite)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.public-knowledge.acceptance.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
