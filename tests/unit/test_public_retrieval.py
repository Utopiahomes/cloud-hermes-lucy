from __future__ import annotations

from datetime import UTC, datetime

import pytest

from lucy.public_contracts import (
    PublicHistoryTurn,
    PublicKnowledgeEntry,
    PublicPageContext,
    PublicReference,
)
from lucy.public_retrieval import (
    GroundingViolation,
    PublicKnowledgeRetriever,
    restricted_topic,
    validate_extractively_grounded_answer,
)

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def reference(identifier: str, label: str, path: str) -> PublicReference:
    return PublicReference(
        id=identifier,
        label=label,
        href=f"https://www.utopiahomes.com{path}",
    )


def entry(
    identifier: str,
    text: str,
    topics: tuple[str, ...],
    *,
    slug: str | None = None,
    aliases: tuple[str, ...] = (),
    effective_from: datetime = datetime(2026, 1, 1, tzinfo=UTC),
    effective_until: datetime | None = None,
) -> PublicKnowledgeEntry:
    route = "property" if slug else "design"
    path = f"/stays/{slug}" if slug else "/design"
    return PublicKnowledgeEntry.model_validate(
        {
            "id": identifier,
            "service_line": "homes" if slug else "design",
            "kind": "fact",
            "title": identifier.replace("-", " "),
            "approved_text": text,
            "aliases": aliases,
            "topics": topics,
            "route": route,
            "property_slug": slug,
            "source": reference(f"{identifier}-source", "Utopia Homes", path),
            "links": (reference(f"{identifier}-link", "Explore", path),),
            "effective_from": effective_from,
            "effective_until": effective_until,
            "direct_answer": True,
        }
    )


ENTRIES = (
    entry(
        "buttercup-summary",
        "Buttercup Beauty is a seven-bedroom Wildwood Crest home with a private pool.",
        ("bedrooms", "location", "pool"),
        slug="buttercup-beauty",
        aliases=("Buttercup", "large group beach home"),
    ),
    entry(
        "buttercup-parking",
        "Buttercup Beauty’s published parking guidance allows four cars.",
        ("parking",),
        slug="buttercup-beauty",
        aliases=("cars", "driveway"),
    ),
    entry(
        "buttercup-capacity",
        "Buttercup Beauty’s approved guest capacity is 20 people.",
        ("capacity",),
        slug="buttercup-beauty",
    ),
    entry(
        "central-pool",
        "Central Ave Socialization has a private pool and hot tub.",
        ("pool",),
        slug="central-ave-socialization",
    ),
    entry(
        "shamrock-summary",
        "The Shamrock is designed for especially large groups and does not publish a pool.",
        ("capacity", "pool"),
        slug="the-shamrock",
    ),
    entry(
        "design-estimate",
        (
            "Utopia Design creates a nonbinding preliminary estimate from the project details "
            "you provide."
        ),
        ("design", "estimate"),
        aliases=("quote", "pricing explanation"),
    ),
)


def test_follow_up_uses_history_only_to_resolve_subject_and_retrieves_facts_again() -> None:
    result = PublicKnowledgeRetriever().retrieve(
        question="How many cars fit?",
        entries=ENTRIES,
        history=(
            PublicHistoryTurn(role="visitor", content="Tell me about Buttercup."),
            PublicHistoryTurn(role="lucy", content="Buttercup is in Wildwood Crest."),
        ),
        observed_at=NOW,
    )
    assert result.outcome == "answered"
    assert "four cars" in result.answer
    assert result.evidence_ids == ("buttercup-parking",)


def test_comparison_with_different_vocabulary_retrieves_multiple_properties() -> None:
    result = PublicKnowledgeRetriever().retrieve(
        question="Which homes have swimming options, and how do they differ?",
        entries=ENTRIES,
        observed_at=NOW,
    )
    assert result.outcome == "answered"
    assert "Buttercup Beauty" in result.answer
    assert "Central Ave Socialization" in result.answer


def test_multiple_requirements_are_covered_individually() -> None:
    result = PublicKnowledgeRetriever().retrieve(
        question="We have 20 people, four cars, and want a pool at Buttercup.",
        entries=ENTRIES,
        observed_at=NOW,
    )
    assert result.outcome == "answered"
    assert {"buttercup-capacity", "buttercup-parking", "buttercup-summary"}.issubset(
        set(result.evidence_ids)
    )


def test_missing_seasonal_detail_returns_supported_partial_answer() -> None:
    result = PublicKnowledgeRetriever().retrieve(
        question="Is the Buttercup pool open in November?",
        entries=ENTRIES,
        observed_at=NOW,
    )
    assert result.outcome == "partial"
    assert "private pool" in result.answer
    assert result.missing_topics == ("pool_season",)
    assert result.clarification is not None


def test_published_design_estimate_explanation_is_not_blocked_as_live_stay_pricing() -> None:
    assert restricted_topic("How does your design estimate work?") is None
    result = PublicKnowledgeRetriever().retrieve(
        question="How does your design estimate work?",
        entries=ENTRIES,
        page_context=PublicPageContext(route="design"),
        observed_at=NOW,
    )
    assert result.outcome == "answered"
    assert "nonbinding preliminary estimate" in result.answer


def test_live_stay_data_and_individual_reservations_are_distinguished_from_general_booking() -> (
    None
):
    assert restricted_topic("What is the nightly price for a stay?") == "live_stay_pricing"
    assert restricted_topic("Do you have dates available next week?") == "live_availability"
    assert restricted_topic("Can you cancel my reservation?") == "reservation_access"
    assert restricted_topic("How does the booking process work?") is None


def test_expired_and_future_facts_are_ineligible_on_every_retrieval_path() -> None:
    expired = entry(
        "expired-parking",
        "An obsolete parking statement.",
        ("parking",),
        slug="buttercup-beauty",
        effective_until=datetime(2026, 9, 1, tzinfo=UTC),
    )
    future = entry(
        "future-parking",
        "A future parking statement.",
        ("parking",),
        slug="buttercup-beauty",
        effective_from=datetime(2026, 10, 1, tzinfo=UTC),
    )
    result = PublicKnowledgeRetriever().retrieve(
        question="How many cars fit at Buttercup?",
        entries=(expired, future),
        observed_at=NOW,
    )
    assert result.outcome == "fallback"
    assert result.evidence_ids == ()


def test_wrong_property_facts_do_not_satisfy_scoped_question() -> None:
    result = PublicKnowledgeRetriever().retrieve(
        question="How many cars fit?",
        entries=ENTRIES,
        page_context=PublicPageContext(route="property", property_slug="buttercup-beauty"),
        history=(
            PublicHistoryTurn(role="lucy", content="The Shamrock has room for large groups."),
        ),
        observed_at=NOW,
    )
    assert result.evidence_ids == ("buttercup-parking",)
    assert "Shamrock" not in result.answer


@pytest.mark.parametrize(
    "unsupported_answer",
    [
        "Buttercup Beauty’s published parking guidance allows six cars.",
        "Central Ave Socialization’s published parking guidance allows four cars.",
        "Buttercup Beauty’s published parking guidance does not allow four cars.",
        "Buttercup Beauty always allows four cars, including policy exceptions.",
    ],
)
def test_valid_citation_cannot_cover_an_unsupported_claim(unsupported_answer: str) -> None:
    cited_entry = next(item for item in ENTRIES if item.id == "buttercup-parking")
    with pytest.raises(GroundingViolation):
        validate_extractively_grounded_answer(unsupported_answer, [cited_entry])


def test_exact_approved_text_is_grounded() -> None:
    cited_entry = next(item for item in ENTRIES if item.id == "buttercup-parking")
    assert (
        validate_extractively_grounded_answer(cited_entry.approved_text, [cited_entry])
        == cited_entry.approved_text
    )
