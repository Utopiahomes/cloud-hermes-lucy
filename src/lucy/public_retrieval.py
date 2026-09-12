"""Deterministic retrieval and coverage gates over approved public knowledge."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal

from lucy.public_contracts import (
    PublicHistoryTurn,
    PublicKnowledgeEntry,
    PublicPageContext,
    PublicReference,
    PublicRetrievalResult,
)

_TOKENS = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a",
    "about",
    "an",
    "and",
    "are",
    "can",
    "does",
    "do",
    "for",
    "have",
    "how",
    "homes",
    "i",
    "in",
    "is",
    "it",
    "me",
    "my",
    "of",
    "on",
    "other",
    "provide",
    "tell",
    "the",
    "to",
    "utopia",
    "want",
    "we",
    "what",
    "which",
    "with",
    "you",
    "your",
}
_SYNONYMS = {
    "automobile": "parking",
    "car": "parking",
    "cars": "parking",
    "cost": "pricing",
    "costs": "pricing",
    "dog": "pets",
    "dogs": "pets",
    "guest": "capacity",
    "guests": "capacity",
    "manage": "owners",
    "management": "owners",
    "people": "capacity",
    "price": "pricing",
    "prices": "pricing",
    "pools": "pool",
    "quote": "estimate",
    "rates": "pricing",
    "sleep": "capacity",
    "sleeps": "capacity",
    "swim": "pool",
    "swimming": "pool",
}
_PROPERTY_ALIASES = {
    "buttercup-beauty": ("buttercup", "buttercup beauty"),
    "central-ave-socialization": ("central ave", "central avenue", "central ave socialization"),
    "the-shamrock": ("shamrock", "the shamrock"),
}
_MONTHS = {
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "winter",
    "spring",
    "summer",
    "fall",
}
_NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}


class GroundingViolation(ValueError):
    """A proposed public answer contains text outside its approved evidence."""


def validate_extractively_grounded_answer(
    answer: str, entries: list[PublicKnowledgeEntry]
) -> str:
    """Require every delivered segment to be exact approved text.

    R1 deliberately uses an extractive boundary. A future inference service may
    choose and order evidence, but a valid citation id alone cannot authorize a
    paraphrase, altered number, negation, or policy exception.
    """

    approved_segments = {entry.approved_text.strip() for entry in entries}
    delivered_segments = [segment.strip() for segment in answer.split("\n") if segment.strip()]
    if not delivered_segments or any(
        segment not in approved_segments for segment in delivered_segments
    ):
        raise GroundingViolation("public answer is not supported by exact approved evidence")
    return " ".join(delivered_segments)


def _normalize(value: str) -> set[str]:
    tokens = {_SYNONYMS.get(token, token) for token in _TOKENS.findall(value.casefold())}
    return tokens - _STOP_WORDS


def _property_in(value: str) -> str | None:
    lowered = " ".join(value.casefold().split())
    for slug, aliases in _PROPERTY_ALIASES.items():
        if any(alias in lowered for alias in aliases):
            return slug
    return None


def _property_scope(
    question: str, page_context: PublicPageContext | None, history: tuple[PublicHistoryTurn, ...]
) -> str | None:
    explicit = _property_in(question)
    if explicit is not None:
        return explicit
    if page_context is not None and page_context.property_slug is not None:
        return page_context.property_slug
    for turn in reversed(history):
        remembered = _property_in(turn.content)
        if remembered is not None:
            return remembered
    return None


def _minimum_requirement(question: str, nouns: tuple[str, ...]) -> int | None:
    alternatives = "|".join(nouns)
    match = re.search(
        rf"\b(\d{{1,3}}|{'|'.join(_NUMBER_WORDS)})\s+(?:{alternatives})\b",
        question.casefold(),
    )
    if match is None:
        return None
    value = match.group(1)
    return int(value) if value.isdigit() else _NUMBER_WORDS[value]


def _matching_property_slugs(
    question: str, entries: list[PublicKnowledgeEntry]
) -> set[str] | None:
    """Return homes satisfying explicit structured requirements, if any were supplied."""

    tokens = _normalize(question)
    min_guests = _minimum_requirement(question, ("people", "guests"))
    min_parking = _minimum_requirement(question, ("cars", "vehicles"))
    wants_pool = "pool" in tokens or "swim" in tokens
    wants_hot_tub = "hot tub" in question.casefold()
    wants_pets = bool({"pet", "pets", "dog", "dogs"} & set(_TOKENS.findall(question.casefold())))
    requirements = (min_guests, min_parking, wants_pool, wants_hot_tub, wants_pets)
    if all(value is None or value is False for value in requirements):
        return None

    facts_by_slug = {
        entry.property_slug: entry.property_facts
        for entry in entries
        if entry.property_slug is not None and entry.property_facts is not None
    }
    return {
        slug
        for slug, facts in facts_by_slug.items()
        if facts is not None
        and (min_guests is None or facts.max_guests >= min_guests)
        and (min_parking is None or facts.parking_spaces >= min_parking)
        and (not wants_pool or facts.has_pool)
        and (not wants_hot_tub or facts.has_hot_tub)
        and (not wants_pets or facts.pets_allowed)
    }


def requested_topics(question: str) -> set[str]:
    lowered = question.casefold()
    tokens = _normalize(question)
    topics = tokens & {
        "bathrooms",
        "bedrooms",
        "booking",
        "capacity",
        "design",
        "estimate",
        "location",
        "membership",
        "owners",
        "parking",
        "pets",
        "pool",
        "pricing",
    }
    if "pool" in topics and ({token for token in tokens if token in _MONTHS} or "open" in tokens):
        topics.add("pool_season")
    if "design" in lowered and ({"estimate", "pricing"} & tokens):
        topics.update({"design", "estimate"})
        topics.discard("pricing")
    return topics


def restricted_topic(
    question: str,
) -> Literal["live_stay_pricing", "live_availability", "reservation_access"] | None:
    lowered = " ".join(question.casefold().split())
    tokens = _normalize(question)
    design_estimate = "design" in tokens and ({"estimate", "pricing"} & tokens)
    stay_context = bool({"stay", "stays", "night", "nights", "booking", "book"} & tokens)
    if not design_estimate and "pricing" in tokens and stay_context:
        return "live_stay_pricing"
    if {"available", "availability"} & tokens and (
        {"date", "dates", "night", "nights", "booking", "book"} & tokens
    ):
        return "live_availability"
    if ("my reservation" in lowered or "my booking" in lowered) and (
        {"change", "cancel", "confirmation", "status", "access"} & tokens
    ):
        return "reservation_access"
    return None


def _unique_references(
    entries: list[PublicKnowledgeEntry], attribute: str
) -> tuple[PublicReference, ...]:
    result: list[PublicReference] = []
    seen: set[str] = set()
    for entry in entries:
        references = (entry.source,) if attribute == "source" else entry.links
        for reference in references:
            if reference.id not in seen:
                seen.add(reference.id)
                result.append(reference)
    return tuple(result[:8])


class PublicKnowledgeRetriever:
    """Retrieve only effective records; history may resolve a subject but never supply facts."""

    def retrieve(
        self,
        *,
        question: str,
        entries: tuple[PublicKnowledgeEntry, ...],
        page_context: PublicPageContext | None = None,
        history: tuple[PublicHistoryTurn, ...] = (),
        observed_at: datetime | None = None,
    ) -> PublicRetrievalResult:
        now = observed_at or datetime.now(UTC)
        eligible = [entry for entry in entries if entry.effective_at(now)]
        restriction = restricted_topic(question)
        if restriction is not None:
            return PublicRetrievalResult(
                outcome="fallback",
                answer=(
                    "I can explain Utopia’s public booking process, but I can’t access live stay "
                    "pricing, availability, or an individual reservation here."
                ),
                restriction=restriction,
            )

        question_tokens = _normalize(question)
        topics = requested_topics(question)
        property_slug = _property_scope(question, page_context, history)
        comparison = (
            bool({"compare", "versus", "vs"} & question_tokens)
            or "which homes" in question.casefold()
        )
        matching_property_slugs = _matching_property_slugs(question, eligible)
        if property_slug is None and matching_property_slugs is not None:
            eligible = [
                entry
                for entry in eligible
                if entry.property_slug is None or entry.property_slug in matching_property_slugs
            ]
        if property_slug is not None and not comparison:
            eligible = [
                entry
                for entry in eligible
                if entry.property_slug is None or entry.property_slug == property_slug
            ]
        scored: list[tuple[int, PublicKnowledgeEntry]] = []
        for entry in eligible:
            entry_topics = set(entry.topics)
            if topics and not (topics & entry_topics):
                continue
            searchable = _normalize(
                " ".join(
                    (
                        entry.title,
                        entry.approved_text,
                        *entry.aliases,
                        *entry.topics,
                        entry.property_slug or "",
                    )
                )
            )
            score = 3 * len(question_tokens & searchable)
            score += 6 * len(topics & entry_topics)
            if property_slug is not None and not comparison:
                score += 10 if entry.property_slug == property_slug else -10
            if page_context is not None and entry.route == page_context.route:
                score += 2
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda item: (-item[0], item[1].id))
        selected = [entry for _, entry in scored[:8]]

        if topics and not comparison:
            complete_direct = [
                entry
                for _, entry in scored
                if entry.direct_answer and topics <= set(entry.topics)
            ]
            if complete_direct:
                selected = complete_direct[:1]

        if not selected:
            return PublicRetrievalResult(
                outcome="fallback",
                answer=(
                    "I don’t have enough approved information to answer that yet. "
                    "You can explore the site or contact Utopia Homes for help."
                ),
            )

        covered = set().union(*(set(entry.topics) for entry in selected))
        missing = tuple(sorted(topics - covered))
        answered_topics = topics & covered
        if topics and not answered_topics:
            return PublicRetrievalResult(
                outcome="fallback",
                answer=(
                    "I found related public information, but not enough to answer that question."
                ),
                missing_topics=tuple(sorted(topics)),
            )

        # Direct approved text, not model-generated claims, is the safe R1 baseline.
        segments = list(dict.fromkeys(entry.approved_text.strip() for entry in selected[:5]))
        answer = validate_extractively_grounded_answer("\n".join(segments), selected)
        outcome: Literal["answered", "partial"] = "partial" if missing else "answered"
        clarification = None
        if missing:
            readable = ", ".join(topic.replace("_", " ") for topic in missing)
            clarification = f"I don’t yet have approved information for: {readable}."
        return PublicRetrievalResult(
            outcome=outcome,
            answer=answer,
            clarification=clarification,
            sources=_unique_references(selected, "source"),
            links=_unique_references(selected, "links"),
            evidence_ids=tuple(entry.id for entry in selected),
            missing_topics=missing,
        )
