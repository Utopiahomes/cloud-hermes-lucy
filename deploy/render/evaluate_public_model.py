"""Run capped, synthetic, full-packet Public Lucy model conversations."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from lucy.public_contracts import (
    PublicHistoryTurn,
    PublicKnowledgeSnapshot,
    PublicPageContext,
)
from lucy.public_model import (
    PublicConversationEngine,
    PublicJsonModel,
    PublicModelCall,
    PublicModelCompletion,
    PublicModelRejected,
)
from lucy.public_openrouter import OpenRouterPublicError, OpenRouterPublicJsonModel

AUTHORIZED_TOTAL_MICROUSD = 5_000_000
GENERATOR_RESERVATION_MICROUSD = 30_000
VERIFIER_RESERVATION_MICROUSD = 15_000
VERIFIER_MODEL = "google/gemini-3.1-flash-lite"
MODELS = (
    "openai/gpt-5-mini",
    "google/gemini-3.1-flash-lite",
    "anthropic/claude-haiku-4.5",
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExpectedTurn(StrictModel):
    question: str = Field(min_length=2, max_length=500)
    page_context: PublicPageContext | None = None
    allowed_outcomes: tuple[Literal["answered", "partial", "fallback"], ...]
    required_term_groups: tuple[tuple[str, ...], ...] = ()
    forbidden_terms: tuple[str, ...] = ()
    required_evidence_ids: tuple[str, ...] = ()
    forbidden_evidence_prefixes: tuple[str, ...] = ()
    evidence_policy: Literal["none", "some", "any"]
    max_characters: int = Field(ge=1, le=8_000)


class ExpectedConversation(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,99}$")
    initial_history: tuple[PublicHistoryTurn, ...] = Field(default=(), max_length=6)
    turns: tuple[ExpectedTurn, ...] = Field(min_length=1, max_length=6)


class EvaluationSuite(StrictModel):
    schema_name: Literal["lucy-public-model-evaluation-v1"] = Field(alias="schema")
    conversations: tuple[ExpectedConversation, ...] = Field(min_length=1, max_length=100)


class RecordingModel:
    def __init__(self, inner: PublicJsonModel) -> None:
        self._inner = inner
        self.calls: list[PublicModelCall] = []
        self.completions: list[PublicModelCompletion] = []

    def complete(self, call: PublicModelCall) -> PublicModelCompletion:
        self.calls.append(call)
        result = self._inner.complete(call)
        self.completions.append(result)
        return result


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _price_ceiling(model: str) -> tuple[float, float]:
    if model == "anthropic/claude-haiku-4.5":
        return 1.5, 6.0
    return 0.8, 4.0


def _provider(
    api_key: str, model: str, allowed_providers: tuple[str, ...]
) -> OpenRouterPublicJsonModel:
    prompt, completion = _price_ceiling(model)
    return OpenRouterPublicJsonModel(
        api_key=api_key,
        model=model,
        allowed_providers=allowed_providers,
        maximum_prompt_usd_per_million=prompt,
        maximum_completion_usd_per_million=completion,
    )


def _score(
    turn: ExpectedTurn, *, outcome: str, answer: str, evidence: tuple[str, ...]
) -> list[str]:
    failures: list[str] = []
    lowered = answer.casefold()
    if outcome not in turn.allowed_outcomes:
        failures.append("outcome")
    for index, alternatives in enumerate(turn.required_term_groups):
        if not any(term.casefold() in lowered for term in alternatives):
            failures.append(f"required_terms_{index}")
    if any(term.casefold() in lowered for term in turn.forbidden_terms):
        failures.append("forbidden_term")
    if not set(turn.required_evidence_ids) <= set(evidence):
        failures.append("required_evidence")
    if any(
        identifier.startswith(prefix)
        for prefix in turn.forbidden_evidence_prefixes
        for identifier in evidence
    ):
        failures.append("forbidden_evidence")
    if turn.evidence_policy == "none" and evidence:
        failures.append("unexpected_evidence")
    if turn.evidence_policy == "some" and not evidence:
        failures.append("missing_evidence")
    if len(answer) > turn.max_characters:
        failures.append("answer_length")
    return failures


def evaluate(
    *,
    api_key: str,
    snapshot: PublicKnowledgeSnapshot,
    suite: EvaluationSuite,
    models: tuple[str, ...],
    repeats: int,
    conversation_ids: tuple[str, ...] = (),
    allowed_providers: tuple[str, ...] = (),
) -> dict[str, object]:
    conversations = tuple(
        item
        for item in suite.conversations
        if not conversation_ids or item.id in conversation_ids
    )
    if not conversations:
        raise ValueError("conversation filter selected no evaluation cases")
    turns_per_repeat = sum(len(item.turns) for item in conversations)
    reserved = (
        turns_per_repeat
        * len(models)
        * repeats
        * (GENERATOR_RESERVATION_MICROUSD + VERIFIER_RESERVATION_MICROUSD)
    )
    if reserved > AUTHORIZED_TOTAL_MICROUSD:
        raise ValueError("planned evaluation reservations exceed the authorized cap")

    runs: list[dict[str, object]] = []
    provider_reported_cost = 0
    ambiguous_reserved_cost = 0
    for model in models:
        for repeat in range(1, repeats + 1):
            generator = RecordingModel(_provider(api_key, model, allowed_providers))
            verifier = RecordingModel(
                _provider(api_key, VERIFIER_MODEL, allowed_providers)
            )
            engine = PublicConversationEngine(
                generator,
                verifier,
                generator_maximum_microusd=GENERATOR_RESERVATION_MICROUSD,
                verifier_maximum_microusd=VERIFIER_RESERVATION_MICROUSD,
                timeout_seconds=45,
            )
            for conversation in conversations:
                history = list(conversation.initial_history)
                for turn_index, turn in enumerate(conversation.turns, start=1):
                    started = time.perf_counter()
                    record: dict[str, object] = {
                        "model": model,
                        "repeat": repeat,
                        "conversation_id": conversation.id,
                        "turn": turn_index,
                        "question": turn.question,
                    }
                    generator_before = len(generator.completions)
                    verifier_before = len(verifier.completions)
                    generator_calls_before = len(generator.calls)
                    verifier_calls_before = len(verifier.calls)
                    try:
                        result = engine.answer(
                            question=turn.question,
                            entries=snapshot.entries,
                            page_context=turn.page_context,
                            history=tuple(history[-6:]),
                        )
                        failures = _score(
                            turn,
                            outcome=result.answer.outcome,
                            answer=result.answer.answer,
                            evidence=result.answer.evidence_ids,
                        )
                        record.update(
                            {
                                "status": "passed" if not failures else "failed",
                                "failures": failures,
                                "outcome": result.answer.outcome,
                                "answer": result.answer.answer,
                                "evidence_ids": list(result.answer.evidence_ids),
                                "source_ids": [item.id for item in result.answer.sources],
                                "link_ids": [item.id for item in result.answer.links],
                                "generator": {
                                    "resolved_model": result.usage.generator.model,
                                    "provider": result.usage.generator.provider,
                                    "prompt_tokens": result.usage.generator.prompt_tokens,
                                    "completion_tokens": result.usage.generator.completion_tokens,
                                    "cost_microusd": result.usage.generator.incurred_microusd,
                                },
                                "verifier": {
                                    "resolved_model": result.usage.verifier.model,
                                    "provider": result.usage.verifier.provider,
                                    "prompt_tokens": result.usage.verifier.prompt_tokens,
                                    "completion_tokens": result.usage.verifier.completion_tokens,
                                    "cost_microusd": result.usage.verifier.incurred_microusd,
                                },
                            }
                        )
                        history.extend(
                            (
                                PublicHistoryTurn(role="visitor", content=turn.question),
                                PublicHistoryTurn(
                                    role="lucy", content=result.answer.answer[:1_000]
                                ),
                            )
                        )
                    except (PublicModelRejected, OpenRouterPublicError, RuntimeError) as exc:
                        record.update(
                            {
                                "status": "error",
                                "error_type": type(exc).__name__,
                                "error": str(exc),
                            }
                        )
                        generated = generator.completions[generator_before:]
                        checked = verifier.completions[verifier_before:]
                        record["completed_model_calls"] = [
                            {
                                "purpose": "answer",
                                "resolved_model": item.model,
                                "provider": item.provider,
                                "prompt_tokens": item.prompt_tokens,
                                "completion_tokens": item.completion_tokens,
                                "cost_microusd": item.incurred_microusd,
                                "synthetic_output": item.content,
                            }
                            for item in generated
                        ] + [
                            {
                                "purpose": "verify",
                                "resolved_model": item.model,
                                "provider": item.provider,
                                "prompt_tokens": item.prompt_tokens,
                                "completion_tokens": item.completion_tokens,
                                "cost_microusd": item.incurred_microusd,
                                "synthetic_output": item.content,
                            }
                            for item in checked
                        ]
                    completed_calls = (
                        generator.completions[generator_before:]
                        + verifier.completions[verifier_before:]
                    )
                    attempted_calls = (
                        generator.calls[generator_calls_before:]
                        + verifier.calls[verifier_calls_before:]
                    )
                    reported = sum(item.incurred_microusd for item in completed_calls)
                    ambiguous_count = len(attempted_calls) - len(completed_calls)
                    ambiguous = sum(
                        item.maximum_microusd
                        for item in attempted_calls[-ambiguous_count:]
                    ) if ambiguous_count else 0
                    provider_reported_cost += reported
                    ambiguous_reserved_cost += ambiguous
                    record["provider_reported_cost_microusd"] = reported
                    record["ambiguous_reserved_cost_microusd"] = ambiguous
                    if (
                        provider_reported_cost + ambiguous_reserved_cost
                        > AUTHORIZED_TOTAL_MICROUSD
                    ):
                        raise RuntimeError("accounted evaluation spend exceeded the authorized cap")
                    record["latency_ms"] = round((time.perf_counter() - started) * 1_000)
                    runs.append(record)
                    print(
                        f"{model} repeat={repeat} {conversation.id}/{turn_index}: "
                        f"{record['status']} {record['latency_ms']}ms",
                        flush=True,
                    )
    passed = sum(record["status"] == "passed" for record in runs)
    completed = sum(record["status"] in {"passed", "failed"} for record in runs)
    return {
        "contract": "lucy.utopia.public-model-evaluation.v1",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "synthetic_only": True,
        "public_corpus_only": True,
        "transcript_capture_changed": False,
        "production_changed": False,
        "authorized_cap_microusd": AUTHORIZED_TOTAL_MICROUSD,
        "planned_reservation_microusd": reserved,
        "provider_reported_cost_microusd": provider_reported_cost,
        "ambiguous_reserved_cost_microusd": ambiguous_reserved_cost,
        "accounted_cost_microusd": provider_reported_cost + ambiguous_reserved_cost,
        "models": list(models),
        "allowed_providers": list(allowed_providers),
        "verifier_model": VERIFIER_MODEL,
        "repeats": repeats,
        "summary": {
            "passed": passed,
            "completed": completed,
            "total": len(runs),
            "pass_rate": passed / len(runs) if runs else 0,
        },
        "runs": runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=Path("deploy/render/utopia-public-knowledge.r1.json"),
    )
    parser.add_argument(
        "--suite",
        type=Path,
        default=Path("deploy/render/public_model_acceptance.v1.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--models", nargs="*", default=list(MODELS))
    parser.add_argument("--conversation", action="append", default=[])
    parser.add_argument("--allowed-provider", action="append", default=[])
    args = parser.parse_args()
    if args.repeats not in range(1, 6):
        raise ValueError("repeats must be between one and five")
    models = tuple(args.models)
    if not models or any(model not in MODELS for model in models):
        raise ValueError("models must come from the reviewed evaluation set")
    values: Mapping[str, str] = {**os.environ, **_read_env_file(args.env_file)}
    api_key = values.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is unavailable")
    snapshot = PublicKnowledgeSnapshot.model_validate_json(args.snapshot.read_text("utf-8"))
    suite = EvaluationSuite.model_validate_json(args.suite.read_text("utf-8"))
    report = evaluate(
        api_key=api_key,
        snapshot=snapshot,
        suite=suite,
        models=models,
        repeats=args.repeats,
        conversation_ids=tuple(args.conversation),
        allowed_providers=tuple(args.allowed_provider),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = report["summary"]
    if not isinstance(summary, dict):
        raise RuntimeError("evaluation summary is invalid")
    print(json.dumps(summary, separators=(",", ":")), flush=True)
    print(
        f"provider_reported_cost_microusd={report['provider_reported_cost_microusd']}",
        flush=True,
    )
    print(f"accounted_cost_microusd={report['accounted_cost_microusd']}", flush=True)
    return 0 if summary.get("passed") == summary.get("total") else 1


if __name__ == "__main__":
    raise SystemExit(main())
