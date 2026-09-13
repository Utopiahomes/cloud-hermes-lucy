from __future__ import annotations

import json
from pathlib import Path

import pytest

from deploy.render.validate_public_knowledge import validate_candidate


def candidate_entry() -> dict[str, object]:
    return {
        "id": "buttercup-summary",
        "service_line": "homes",
        "kind": "fact",
        "title": "Buttercup summary",
        "approved_text": "Buttercup Beauty welcomes up to 22 guests.",
        "aliases": ["Buttercup"],
        "topics": ["capacity"],
        "route": "property",
        "property_slug": "buttercup-beauty",
        "property_facts": {
            "max_guests": 22,
            "parking_spaces": 4,
            "has_pool": True,
            "has_hot_tub": True,
            "bedrooms": 7,
            "bathrooms": 3.5,
            "pets_allowed": True,
        },
        "source": {
            "id": "buttercup-page",
            "label": "Buttercup Beauty",
            "href": "https://www.utopiahomes.com/stays/buttercup-beauty",
        },
        "links": [],
        "effective_from": "2026-09-12T00:00:00Z",
        "direct_answer": True,
    }


def write_candidate(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps({"schema": "lucy-public-knowledge-v1", "entries": entries}),
        encoding="utf-8",
    )


def test_validator_reports_stable_digest_without_staging(tmp_path: Path) -> None:
    path = tmp_path / "candidate.json"
    write_candidate(path, [candidate_entry()])
    count, first_digest = validate_candidate(path)
    _, second_digest = validate_candidate(path)
    assert count == 1
    assert first_digest == second_digest


def test_validator_rejects_inconsistent_duplicate_property_facts(tmp_path: Path) -> None:
    path = tmp_path / "candidate.json"
    changed = candidate_entry() | {"id": "buttercup-other"}
    changed["property_facts"] = dict(changed["property_facts"], parking_spaces=6)  # type: ignore[arg-type]
    write_candidate(path, [candidate_entry(), changed])
    with pytest.raises(ValueError, match="consistent"):
        validate_candidate(path)
