from __future__ import annotations

import json
from pathlib import Path

import pytest

from deploy.render.evaluate_public_knowledge import AcceptanceFailure, evaluate

ROOT = Path(__file__).parents[2]


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def knowledge_entry() -> dict[str, object]:
    return {
        "id": "design-estimate",
        "service_line": "design",
        "kind": "policy",
        "title": "Design estimate",
        "approved_text": "Utopia Design provides a nonbinding preliminary estimate.",
        "aliases": ["quote"],
        "topics": ["design", "estimate"],
        "route": "design",
        "source": {
            "id": "design-page",
            "label": "Utopia Design",
            "href": "https://www.utopiahomes.com/design",
        },
        "links": [],
        "effective_from": "2026-01-01T00:00:00Z",
        "direct_answer": True,
    }


def acceptance_case(*, evidence: list[str]) -> dict[str, object]:
    return {
        "contract": "lucy.public-knowledge.acceptance.v1",
        "cases": [
            {
                "id": "design-estimate",
                "question": "How does your design estimate work?",
                "history": [],
                "expected_outcome": "answered",
                "expected_evidence_ids": evidence,
                "expected_missing_topics": [],
            }
        ],
    }


def test_evaluator_requires_exact_evidence_selection(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    suite = tmp_path / "suite.json"
    write_json(
        candidate,
        {"schema": "lucy-public-knowledge-v1", "entries": [knowledge_entry()]},
    )
    write_json(suite, acceptance_case(evidence=["design-estimate"]))
    assert evaluate(candidate, suite)["status"] == "passed"

    write_json(suite, acceptance_case(evidence=["unrelated-evidence"]))
    with pytest.raises(AcceptanceFailure, match="design-estimate"):
        evaluate(candidate, suite)


def test_repository_acceptance_suite_is_strict_and_bounded() -> None:
    suite = json.loads(
        (ROOT / "deploy/render/public_knowledge_acceptance.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert suite["contract"] == "lucy.public-knowledge.acceptance.v1"
    assert len(suite["cases"]) == 10
    assert len({case["id"] for case in suite["cases"]}) == 10
