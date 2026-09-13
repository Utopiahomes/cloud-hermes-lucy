from __future__ import annotations

import pytest

from lucy.publication import faq_snapshot, knowledge_snapshot, snapshot_digest
from lucy.tenancy import normalize_hostname


def test_hostname_normalization_is_strict_and_stable() -> None:
    assert normalize_hostname(" UtopiaHomes.COM. ") == "utopiahomes.com"
    for invalid in ("", "localhost", "https://utopiahomes.com", "utopiahomes.com:443"):
        with pytest.raises(ValueError, match="invalid hostname"):
            normalize_hostname(invalid)


def test_public_snapshot_digest_is_order_independent_but_content_sensitive() -> None:
    first = faq_snapshot(
        [
            {"question": "Where are you?", "answer": "Delaware", "source": "site/location"},
            {"question": "Do you host?", "answer": "Yes", "source": "site/services"},
        ]
    )
    reordered = faq_snapshot(list(reversed(first["faqs"])))
    changed = faq_snapshot(
        [{"question": "Where are you?", "answer": "Maryland", "source": "site/location"}]
    )
    assert snapshot_digest(first) == snapshot_digest(reordered)
    assert snapshot_digest(first) != snapshot_digest(changed)


def test_public_knowledge_snapshot_is_validated_sorted_and_unique() -> None:
    entry = {
        "id": "buttercup-parking",
        "service_line": "homes",
        "kind": "fact",
        "title": "Buttercup parking",
        "approved_text": "Buttercup Beauty has off-street parking for four cars.",
        "aliases": ["cars"],
        "topics": ["parking"],
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
            "id": "buttercup",
            "label": "Buttercup Beauty",
            "href": "https://www.utopiahomes.com/stays/buttercup-beauty",
        },
        "effective_from": "2026-01-01T00:00:00Z",
        "direct_answer": True,
    }
    snapshot = knowledge_snapshot([entry])
    assert snapshot["schema"] == "lucy-public-knowledge-v1"
    assert snapshot["entries"][0]["id"] == "buttercup-parking"
    with pytest.raises(ValueError, match="unique"):
        knowledge_snapshot([entry, entry])
