from __future__ import annotations

import json
from pathlib import Path

import pytest

from lucy.shared_execution.canonical import canonical_json_bytes
from lucy.shared_execution.service import canonical_identity
from lucy.shared_execution.wire import ExecutionRequest

ROOT = Path(__file__).resolve().parents[2]
OFFICIAL = (
    ROOT
    / "contracts"
    / "stoin-business-guest-answer-v1-bundle"
    / "fixtures"
    / "canonicalization"
    / "official-rfc8785-vectors"
)


@pytest.mark.parametrize("name", ["arrays", "french", "structures", "values", "weird"])
def test_canonicalizer_matches_vendored_official_rfc8785_vectors(name: str) -> None:
    source = json.loads((OFFICIAL / "input" / f"{name}.json").read_bytes())
    expected = (OFFICIAL / "output" / f"{name}.json").read_bytes()
    assert canonical_json_bytes(source) == expected


def test_request_identity_is_independent_of_input_member_order() -> None:
    first = {
        "contract": "stoin.inference.execute.request.v1",
        "execution_profile_id": "utopia-homes.public-answer.generate.v1",
        "messages": [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "question"},
        ],
        "output": {"mode": "text"},
        "limits": {"max_output_tokens": 10, "max_cost_microusd": 20},
    }
    second = {
        "limits": {"max_cost_microusd": 20, "max_output_tokens": 10},
        "output": {"mode": "text"},
        "messages": [
            {"content": "system", "role": "system"},
            {"content": "question", "role": "user"},
        ],
        "execution_profile_id": "utopia-homes.public-answer.generate.v1",
        "contract": "stoin.inference.execute.request.v1",
    }
    assert canonical_identity(ExecutionRequest.model_validate(first)) == canonical_identity(
        ExecutionRequest.model_validate(second)
    )


def test_canonicalizer_rejects_integer_outside_i_json_domain() -> None:
    with pytest.raises(ValueError, match="canonical domain"):
        canonical_json_bytes({"outside": 2**53})
