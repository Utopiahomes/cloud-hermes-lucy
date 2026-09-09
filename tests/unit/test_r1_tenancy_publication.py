from __future__ import annotations

import pytest

from lucy.publication import faq_snapshot, snapshot_digest
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
