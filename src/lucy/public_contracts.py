"""Strict contracts for bounded, approved-public conversation."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class StrictPublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


PublicRoute = Literal[
    "home",
    "stays",
    "property",
    "destinations",
    "destination",
    "owners",
    "design",
    "membership",
    "about",
    "contact",
    "other_public",
]
PropertySlug = Literal[
    "buttercup-beauty",
    "central-ave-socialization",
    "the-shamrock",
]


class PublicPageContext(StrictPublicModel):
    route: PublicRoute
    property_slug: PropertySlug | None = None

    @model_validator(mode="after")
    def property_context_is_complete(self) -> PublicPageContext:
        if (self.route == "property") != (self.property_slug is not None):
            raise ValueError("property context requires exactly one approved property slug")
        return self


class PublicHistoryTurn(StrictPublicModel):
    role: Literal["visitor", "lucy"]
    content: str = Field(min_length=1, max_length=1_000)


class PublicReference(StrictPublicModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    label: str = Field(min_length=1, max_length=160)
    href: HttpUrl

    @model_validator(mode="after")
    def public_utopia_link_only(self) -> PublicReference:
        if self.href.scheme != "https" or self.href.host != "www.utopiahomes.com":
            raise ValueError("public references must use the approved Utopia hostname")
        return self


class PublicKnowledgeEntry(StrictPublicModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    service_line: Literal["homes", "design", "general"]
    kind: Literal["fact", "description", "policy", "navigation", "call_to_action"]
    title: str = Field(min_length=1, max_length=200)
    approved_text: str = Field(min_length=1, max_length=2_000)
    aliases: tuple[str, ...] = Field(default=(), max_length=24)
    topics: tuple[str, ...] = Field(min_length=1, max_length=24)
    route: PublicRoute
    property_slug: PropertySlug | None = None
    source: PublicReference
    links: tuple[PublicReference, ...] = Field(default=(), max_length=8)
    effective_from: datetime
    effective_until: datetime | None = None
    direct_answer: bool = False

    @model_validator(mode="after")
    def validate_scope_and_time(self) -> PublicKnowledgeEntry:
        if self.route == "property" and self.property_slug is None:
            raise ValueError("property knowledge requires an approved property slug")
        if self.route != "property" and self.property_slug is not None:
            raise ValueError("property slug is only valid for property knowledge")
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("knowledge expiration must follow its effective time")
        return self

    def effective_at(self, observed_at: datetime) -> bool:
        return self.effective_from <= observed_at and (
            self.effective_until is None or observed_at < self.effective_until
        )


class PublicKnowledgeSnapshot(StrictPublicModel):
    schema_name: Literal["lucy-public-knowledge-v1"] = Field(alias="schema")
    entries: tuple[PublicKnowledgeEntry, ...] = Field(min_length=1, max_length=500)


class PublicRetrievalResult(StrictPublicModel):
    outcome: Literal["answered", "partial", "fallback"]
    answer: str = Field(min_length=1, max_length=8_000)
    clarification: str | None = Field(default=None, max_length=1_000)
    sources: tuple[PublicReference, ...] = Field(default=(), max_length=8)
    links: tuple[PublicReference, ...] = Field(default=(), max_length=8)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=8)
    missing_topics: tuple[str, ...] = Field(default=(), max_length=12)
    restriction: Literal["live_stay_pricing", "live_availability", "reservation_access"] | None = (
        None
    )
