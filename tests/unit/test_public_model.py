from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from lucy.public_contracts import (
    PublicHistoryTurn,
    PublicKnowledgeEntry,
    PublicPageContext,
    PublicReference,
)
from lucy.public_model import (
    PublicAnswerSegment,
    PublicContextAssembler,
    PublicConversationEngine,
    PublicModelCall,
    PublicModelCompletion,
    PublicModelDraft,
    PublicModelRejected,
    PublicSupportVerdict,
)

NOW = datetime(2026, 9, 13, tzinfo=UTC)


def reference(identifier: str, label: str, path: str) -> PublicReference:
    return PublicReference(
        id=identifier,
        label=label,
        href=f"https://www.utopiahomes.com{path}",
    )


def knowledge(
    identifier: str = "buttercup-capacity",
    text: str = "Buttercup Beauty welcomes up to 22 guests.",
    *,
    effective_from: datetime = datetime(2026, 1, 1, tzinfo=UTC),
    effective_until: datetime | None = None,
) -> PublicKnowledgeEntry:
    return PublicKnowledgeEntry(
        id=identifier,
        service_line="homes",
        kind="fact",
        title="Buttercup Beauty capacity",
        approved_text=text,
        topics=("capacity",),
        route="property",
        property_slug="buttercup-beauty",
        property_facts={
            "max_guests": 22,
            "parking_spaces": 4,
            "has_pool": True,
            "has_hot_tub": True,
            "bedrooms": 7,
            "bathrooms": 3.5,
            "pets_allowed": True,
        },
        source=reference("buttercup-source", "Buttercup Beauty", "/stays/buttercup-beauty"),
        links=(
            reference(
                "buttercup-link", "Explore Buttercup Beauty", "/stays/buttercup-beauty"
            ),
        ),
        effective_from=effective_from,
        effective_until=effective_until,
        direct_answer=True,
    )


def completion(content: dict[str, object], *, cost: int = 10) -> PublicModelCompletion:
    return PublicModelCompletion(
        content=json.dumps(content),
        model="test/model",
        provider="test-provider",
        provider_reference="test-completion-1",
        prompt_tokens=100,
        completion_tokens=20,
        incurred_microusd=cost,
    )


class FakeModel:
    def __init__(self, *responses: PublicModelCompletion) -> None:
        self.responses = list(responses)
        self.calls: list[PublicModelCall] = []

    def complete(self, call: PublicModelCall) -> PublicModelCompletion:
        self.calls.append(call)
        return self.responses.pop(0)


def supported() -> dict[str, object]:
    return {
        "supported": True,
        "unsupported_segment_indexes": [],
        "reason_codes": [],
    }


def test_full_packet_model_answer_is_verified_and_server_resolves_references() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": "Buttercup Beauty welcomes up to 22 guests.",
                        "evidence_ids": ["buttercup-capacity"],
                    }
                ],
                "link_ids": ["buttercup-link"],
            }
        )
    )
    verifier = FakeModel(completion(supported()))

    result = PublicConversationEngine(generator, verifier).answer(
        question="Would Buttercup work for 20 people?",
        entries=(knowledge(),),
        page_context=PublicPageContext(route="stays"),
        observed_at=NOW,
    )

    assert result.answer.outcome == "answered"
    assert result.answer.evidence_ids == ("buttercup-capacity",)
    assert result.answer.sources[0].id == "buttercup-source"
    assert result.answer.links == ()  # identical source/action destinations are not duplicated
    assert result.usage.incurred_microusd == 20
    answer_context = generator.calls[0].messages[1].content
    assert "lucy-public-model-context-v1" in answer_context
    assert "buttercup-capacity" in answer_context
    assert "https://" not in answer_context
    assert "final_answer" in verifier.calls[0].messages[1].content


def test_unknown_stay_length_reaches_model_with_history_and_can_clarify_naturally() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "partial",
                "segments": [
                    {
                        "kind": "conversation",
                        "text": (
                            "Do you mean the minimum number of nights? I don't have approved "
                            "stay-length information yet."
                        ),
                        "evidence_ids": [],
                    }
                ],
                "link_ids": [],
            }
        )
    )
    verifier = FakeModel(completion(supported()))
    history = (
        PublicHistoryTurn(role="visitor", content="What makes Utopia different?"),
        PublicHistoryTurn(role="lucy", content="Utopia has three distinctive properties."),
    )

    result = PublicConversationEngine(generator, verifier).answer(
        question="How long are Utopia stays?",
        entries=(knowledge(),),
        history=history,
        observed_at=NOW,
    )

    assert result.answer.outcome == "partial"
    assert "minimum number of nights" in result.answer.answer
    assert result.answer.evidence_ids == ()
    assert [message.role for message in generator.calls[0].messages[-3:]] == [
        "user",
        "assistant",
        "user",
    ]
    assert generator.calls[0].messages[-1].content == "How long are Utopia stays?"


def test_model_cannot_cite_unknown_evidence_or_link() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": "Buttercup Beauty welcomes up to 22 guests.",
                        "evidence_ids": ["invented"],
                    }
                ],
                "link_ids": [],
            }
        )
    )
    with pytest.raises(PublicModelRejected, match="outside the approved packet"):
        PublicConversationEngine(generator, FakeModel()).answer(
            question="How many guests?", entries=(knowledge(),), observed_at=NOW
        )


def test_exact_business_numbers_must_come_from_question_or_cited_evidence() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": "Buttercup Beauty welcomes up to 29 guests.",
                        "evidence_ids": ["buttercup-capacity"],
                    }
                ],
                "link_ids": [],
            }
        )
    )
    with pytest.raises(PublicModelRejected, match="invented an exact business value"):
        PublicConversationEngine(generator, FakeModel()).answer(
            question="How many guests?", entries=(knowledge(),), observed_at=NOW
        )


def test_final_displayed_answer_must_pass_independent_support_check() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": "Buttercup Beauty welcomes up to 22 guests.",
                        "evidence_ids": ["buttercup-capacity"],
                    }
                ],
                "link_ids": [],
            }
        )
    )
    verifier = FakeModel(
        completion(
            {
                "supported": False,
                "unsupported_segment_indexes": [0],
                "reason_codes": ["unsupported_business_claim"],
            }
        )
    )
    with pytest.raises(PublicModelRejected, match="failed support verification"):
        PublicConversationEngine(generator, verifier).answer(
            question="How many guests?", entries=(knowledge(),), observed_at=NOW
        )


def test_context_assembler_enforces_effective_dates() -> None:
    expired = knowledge(
        "expired",
        "Expired text.",
        effective_until=datetime(2026, 9, 1, tzinfo=UTC),
    )
    future = knowledge(
        "future",
        "Future text.",
        effective_from=datetime(2026, 10, 1, tzinfo=UTC),
    )
    context = PublicContextAssembler().assemble((expired, future, knowledge()), observed_at=NOW)
    assert set(context.entries_by_id) == {"buttercup-capacity"}
    assert "Expired text" not in context.packet
    assert "Future text" not in context.packet


def test_cited_conversation_is_promoted_and_checked_as_a_business_claim() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "partial",
                "segments": [
                    {
                        "kind": "conversation",
                        "text": "Buttercup Beauty welcomes up to 29 guests.",
                        "evidence_ids": ["buttercup-capacity"],
                    }
                ],
                "link_ids": [],
            }
        )
    )
    with pytest.raises(PublicModelRejected, match="invented an exact business value"):
        PublicConversationEngine(generator, FakeModel()).answer(
            question="How many guests?", entries=(knowledge(),), observed_at=NOW
        )


def test_server_can_resolve_any_approved_packet_link_and_sends_it_to_verifier() -> None:
    second = knowledge(
        "booking-external-handoff",
        "Use the stay page to continue to the configured booking destination.",
    )
    generator = FakeModel(
        completion(
            {
                "outcome": "partial",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": (
                            "Use the stay page to continue to the configured booking "
                            "destination."
                        ),
                        "evidence_ids": ["booking-external-handoff"],
                    }
                ],
                "link_ids": ["buttercup-link"],
            }
        )
    )
    verifier = FakeModel(completion(supported()))

    result = PublicConversationEngine(generator, verifier).answer(
        question="Where do I check?", entries=(knowledge(), second), observed_at=NOW
    )

    assert result.answer.links == ()  # selected link duplicates the cited entry's source URL
    assert '"selected_links"' in verifier.calls[0].messages[1].content


@pytest.mark.parametrize(
    "text",
    ("One of our properties is Buttercup Beauty.", "Properties that offer one include Buttercup."),
)
def test_pronoun_one_does_not_trigger_exact_business_number_check(text: str) -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": text,
                        "evidence_ids": ["buttercup-capacity"],
                    }
                ],
                "link_ids": [],
            }
        )
    )

    result = PublicConversationEngine(generator, FakeModel(completion(supported()))).answer(
        question="Which property?", entries=(knowledge(),), observed_at=NOW
    )

    assert result.answer.outcome == "answered"


def test_provider_wire_schemas_require_every_property_for_strict_json_mode() -> None:
    for model in (PublicAnswerSegment, PublicModelDraft, PublicSupportVerdict):
        schema = model.model_json_schema()
        assert set(schema["required"]) == set(schema["properties"])


def test_distinct_evidence_union_is_bounded_before_response_construction() -> None:
    entries = tuple(
        knowledge(f"fact-{index}", f"Approved fact {index}.") for index in range(1, 10)
    )
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": "Approved summary.",
                        "evidence_ids": [f"fact-{index}" for index in range(1, 9)],
                    },
                    {
                        "kind": "business_claim",
                        "text": "One additional approved statement.",
                        "evidence_ids": ["fact-9"],
                    },
                ],
                "link_ids": [],
            }
        )
    )

    with pytest.raises(PublicModelRejected, match="too many distinct evidence"):
        PublicConversationEngine(generator, FakeModel()).answer(
            question="Summarize.", entries=entries, observed_at=NOW
        )


def test_property_facts_cannot_hide_in_an_uncited_conversation_segment() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "answered",
                "segments": [
                    {
                        "kind": "conversation",
                        "text": "Buttercup Beauty welcomes 22 guests.",
                        "evidence_ids": [],
                    }
                ],
                "link_ids": [],
            }
        )
    )

    with pytest.raises(PublicModelRejected, match="outside the evidence boundary"):
        PublicConversationEngine(generator, FakeModel()).answer(
            question="Tell me about Buttercup.", entries=(knowledge(),), observed_at=NOW
        )


def test_property_question_and_explicit_access_boundary_remain_conversational() -> None:
    generator = FakeModel(
        completion(
            {
                "outcome": "partial",
                "segments": [
                    {
                        "kind": "business_claim",
                        "text": "I cannot access live availability for Buttercup Beauty.",
                        "evidence_ids": [],
                    },
                    {
                        "kind": "conversation",
                        "text": "Would you like the Buttercup Beauty page?",
                        "evidence_ids": [],
                    },
                ],
                "link_ids": [],
            }
        )
    )

    result = PublicConversationEngine(generator, FakeModel(completion(supported()))).answer(
        question="Is Buttercup available?", entries=(knowledge(),), observed_at=NOW
    )

    assert result.answer.evidence_ids == ()
    assert "cannot access" in result.answer.answer
