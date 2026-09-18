from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from lucy.shared_execution.api import ERRORS, ApiRelease, _error, create_shared_execution_app
from lucy.shared_execution.auth import (
    InMemoryJtiReplayStore,
    WorkloadIdentity,
    WorkloadJwtVerifier,
    content_sha256,
    request_binding_digest,
)
from lucy.shared_execution.service import (
    ExecutionProfile,
    InMemoryExecutionStore,
    ProviderResult,
    SharedExecutionService,
)
from lucy.shared_execution.wire import CostReceipt, ExecutionRequest

ISSUER = "https://homes.internal"
SUBJECT = "stoin:synth:utopia-homes-prime"
PROFILE = "utopia-homes.public-answer.generate.v1"
KEY_ID = "homes-prime-local-1"
BUNDLE = (
    Path(__file__).resolve().parents[2] / "contracts" / "stoin-shared-model-execution-v1-rc1-bundle"
)


def bundle_validator(name: str) -> Draft202012Validator:
    schemas = BUNDLE / "schemas"
    common = json.loads((schemas / "common.defs.json").read_text(encoding="utf-8"))
    schema = json.loads((schemas / name).read_text(encoding="utf-8"))
    registry = Registry().with_resources([(common["$id"], Resource.from_contents(common))])
    return Draft202012Validator(schema, registry=registry)


class FakeTransport:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ExecutionRequest, profile: ExecutionProfile) -> ProviderResult:
        self.calls += 1
        return ProviderResult(
            content="Candidate answer",
            input_tokens=10,
            generated_tokens=4,
            output_tokens=4,
            reasoning_tokens=0,
            cost_microusd=20,
        )


class InvalidTransport(FakeTransport):
    def execute(self, request: ExecutionRequest, profile: ExecutionProfile) -> ProviderResult:
        result = super().execute(request, profile)
        return ProviderResult(
            content={"unexpected": True},
            input_tokens=result.input_tokens,
            generated_tokens=result.generated_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            cost_microusd=result.cost_microusd,
        )


def body(question: str = "Tell me about Buttercup.") -> bytes:
    payload: dict[str, Any] = {
        "contract": "stoin.inference.execute.request.v1",
        "execution_profile_id": PROFILE,
        "messages": [
            {"role": "system", "content": "Use approved context."},
            {"role": "user", "content": question},
        ],
        "output": {"mode": "text"},
        "limits": {"max_output_tokens": 900, "max_cost_microusd": 2000},
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def setup(
    transport: FakeTransport | None = None,
    authentication_failure_delay: Callable[[float], Awaitable[None]] | None = None,
) -> tuple[TestClient, FakeTransport, Ed25519PrivateKey, InMemoryJtiReplayStore]:
    private_key = Ed25519PrivateKey.generate()
    replay = InMemoryJtiReplayStore()
    identity = WorkloadIdentity(
        issuer=ISSUER,
        subject=SUBJECT,
        realm="utopia-homes",
        environment="local-test",
        keys={KEY_ID: private_key.public_key()},
        execution_profiles=frozenset({PROFILE}),
    )
    transport = transport or FakeTransport()
    profile = ExecutionProfile(
        profile_id=PROFILE,
        release_id="profiles-local.1",
        allowed_modes=frozenset({"text"}),
        maximum_output_tokens=900,
        maximum_cost_microusd=2000,
    )
    service = SharedExecutionService(
        InMemoryExecutionStore(), transport, {profile.profile_id: profile}
    )
    app = create_shared_execution_app(
        service,
        WorkloadJwtVerifier(identity, replay),
        ApiRelease(execution="tiamat-local.1", policy="profiles-local.1"),
        authentication_failure_delay=authentication_failure_delay,
    )
    return TestClient(app), transport, private_key, replay


def headers(
    private_key: Ed25519PrivateKey,
    raw: bytes,
    *,
    key: UUID | None = None,
    jti: UUID | None = None,
    request_id: UUID | None = None,
    declared_hash: str | None = None,
    scope: str = "inference.execute",
) -> dict[str, str]:
    idempotency_key = str(key or uuid4())
    body_hash = declared_hash or content_sha256(raw)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": "stoin:shared-model-execution",
            "scope": scope,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": str(jti or uuid4()),
            "req": request_binding_digest(
                "POST", "/execution/v1/inference", idempotency_key, body_hash
            ),
        },
        private_key,
        algorithm="EdDSA",
        headers={"kid": KEY_ID},
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": str(request_id or uuid4()),
        "Idempotency-Key": idempotency_key,
        "X-Execution-Timeout-Ms": "15000",
        "X-Content-SHA256": body_hash,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def test_authenticated_request_returns_bound_response_and_release_headers() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    request_headers = headers(private_key, raw)
    response = client.post("/execution/v1/inference", content=raw, headers=request_headers)
    assert response.status_code == 200
    assert response.json()["request_id"] == request_headers["X-Request-ID"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-stoin-execution-release"] == "tiamat-local.1"
    assert response.headers["x-stoin-execution-policy-release"] == "profiles-local.1"
    assert "set-cookie" not in response.headers
    assert transport.calls == 1
    bundle_validator("response.schema.json").validate(response.json())


def test_all_frozen_error_messages_and_retry_flags_are_implemented() -> None:
    vectors = {}
    for path in (BUNDLE / "vectors" / "positive").glob("error.pos.*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))["document"]["error"]
        vectors[document["code"]] = (document["message"], document["retryable"])
    assert len(vectors) == 29
    assert set(ERRORS) == set(vectors)
    assert {
        code: (message, retryable) for code, (_status, message, retryable) in ERRORS.items()
    } == vectors


def test_every_implemented_error_envelope_passes_the_frozen_provider_schema() -> None:
    validator = bundle_validator("error.schema.json")
    for code in ERRORS:
        response = _error(code, request_id=str(uuid4()))
        validator.validate(json.loads(response.body))


@pytest.mark.parametrize(
    "cost",
    [
        CostReceipt(
            reserved_microusd=2_000,
            settled_microusd=40,
            settlement_status="settled",
        ),
        CostReceipt(
            reserved_microusd=2_000,
            settled_microusd=None,
            settlement_status="pending_reconciliation",
        ),
        CostReceipt(
            reserved_microusd=2_000,
            settled_microusd=None,
            settlement_status="reservation_forfeited",
        ),
        CostReceipt(
            reserved_microusd=2_000,
            settled_microusd=2_001,
            settlement_status="settlement_overrun",
        ),
    ],
)
def test_every_cost_receipt_variant_passes_the_frozen_error_schema(
    cost: CostReceipt,
) -> None:
    response = _error(
        "provider_response_invalid",
        request_id=str(uuid4()),
        execution=(uuid4(), "failed"),
        cost=cost,
    )
    bundle_validator("error.schema.json").validate(json.loads(response.body))


def test_fresh_jwt_replays_same_operation_without_second_provider_call() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    key = uuid4()
    first = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw, key=key)
    )
    second_headers = headers(private_key, raw, key=key)
    second = client.post("/execution/v1/inference", content=raw, headers=second_headers)
    assert first.status_code == second.status_code == 200
    assert second.json()["execution_id"] == first.json()["execution_id"]
    assert second.json()["replayed"] is True
    assert second.json()["request_id"] == second_headers["X-Request-ID"]
    assert transport.calls == 1


def test_failed_duplicate_replays_authoritative_error_and_cost_receipt() -> None:
    client, transport, private_key, _ = setup(InvalidTransport())
    raw = body()
    key = uuid4()
    first = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, key=key),
    )
    second = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, key=key),
    )
    assert first.status_code == second.status_code == 502
    assert first.json()["error"]["code"] == "provider_response_invalid"
    assert second.json()["error"] == first.json()["error"]
    assert second.json()["execution"] == first.json()["execution"]
    assert second.json()["execution"]["state"] == "failed"
    assert second.json()["cost"] == {
        "reserved_microusd": 2000,
        "settled_microusd": 20,
        "settlement_status": "settled",
    }
    assert transport.calls == 1


def test_reused_jti_is_generic_authentication_failure_without_release_disclosure() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    jti = uuid4()
    first = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw, jti=jti)
    )
    second = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw, jti=jti)
    )
    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["error"] == {
        "code": "authentication_failed",
        "message": "Service authentication failed.",
        "retryable": False,
    }
    assert "x-stoin-execution-release" not in second.headers
    assert transport.calls == 1


def test_invalid_token_precedes_unavailable_replay_store() -> None:
    client, transport, private_key, replay = setup()
    replay.set_available(False)
    raw = body()
    invalid = headers(private_key, raw, scope="wrong")
    invalid_response = client.post("/execution/v1/inference", content=raw, headers=invalid)
    valid_response = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw)
    )
    assert invalid_response.status_code == 401
    assert valid_response.status_code == 503
    assert valid_response.json()["error"]["code"] == "authentication_state_unavailable"
    assert "x-stoin-execution-release" not in valid_response.headers
    assert transport.calls == 0


def test_all_step_three_rejections_use_the_injected_timing_class() -> None:
    starts: list[float] = []

    async def record_delay(started_at: float) -> None:
        starts.append(started_at)

    client, _, private_key, replay = setup(authentication_failure_delay=record_delay)
    raw = body()
    missing_binding = client.post("/execution/v1/inference", content=raw)
    wrong_scope = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, scope="wrong"),
    )
    replay.set_available(False)
    unavailable = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw),
    )
    assert [response.status_code for response in (missing_binding, wrong_scope, unavailable)] == [
        401,
        401,
        503,
    ]
    assert len(starts) == 3


def test_step_six_digest_mismatch_is_exempt_from_step_three_timing_class() -> None:
    starts: list[float] = []

    async def record_delay(started_at: float) -> None:
        starts.append(started_at)

    client, _, private_key, _ = setup(authentication_failure_delay=record_delay)
    raw = body()
    response = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, declared_hash=content_sha256(b"different")),
    )
    assert response.status_code == 401
    assert starts == []


def test_step_six_digest_mismatch_uses_generic_auth_failure_and_no_release_headers() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    wrong_hash = content_sha256(body("Different bytes"))
    response = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, declared_hash=wrong_hash),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_failed"
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_malformed_request_id_is_step_four_after_valid_authentication() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    request_headers = headers(private_key, raw)
    request_headers["X-Request-ID"] = "not-a-uuid"
    response = client.post("/execution/v1/inference", content=raw, headers=request_headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert "request_id" not in response.json()
    assert response.headers["x-stoin-execution-release"] == "tiamat-local.1"
    assert transport.calls == 0


def test_unknown_path_does_not_disclose_release_headers() -> None:
    client, _, private_key, _ = setup()
    raw = body()
    response = client.post("/wrong", content=raw, headers=headers(private_key, raw))
    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": "route_not_found",
        "message": "The requested execution route was not found.",
        "retryable": False,
    }
    assert "x-stoin-execution-release" not in response.headers


def test_unsupported_method_precedes_authentication_and_hides_release_headers() -> None:
    client, transport, _, _ = setup()
    response = client.get("/execution/v1/inference")
    assert response.status_code == 405
    assert response.json()["error"] == {
        "code": "method_not_allowed",
        "message": "The execution method is not allowed.",
        "retryable": False,
    }
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_gross_body_cap_rejects_before_authentication_without_release_headers() -> None:
    client, transport, _, _ = setup()
    response = client.post("/execution/v1/inference", content=b"x" * 1_048_577)
    assert response.status_code == 413
    assert response.json() == {"detail": "request rejected"}
    assert response.headers["cache-control"] == "no-store"
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_malformed_content_length_rejects_before_authentication() -> None:
    client, transport, _, _ = setup()
    response = client.post(
        "/execution/v1/inference",
        content=b"{}",
        headers={"Content-Length": "not-an-integer"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "request rejected"}
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_duplicate_content_length_rejects_at_transport_framing_gate() -> None:
    client, transport, _, _ = setup()
    response = client.post(
        "/execution/v1/inference",
        content=b"{}",
        headers=[("Content-Length", "2"), ("Content-Length", "2")],
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "request rejected"}
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_duplicate_binding_header_is_generic_authentication_failure() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    request_headers = list(headers(private_key, raw).items())
    request_headers.append(("Idempotency-Key", str(uuid4())))
    response = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=request_headers,
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_failed"
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_contract_oversize_authenticates_before_step_five_rejection() -> None:
    client, transport, private_key, replay = setup()
    raw = b"x" * 262_145
    jti = uuid4()
    response = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, jti=jti),
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"
    assert response.headers["x-stoin-execution-release"] == "tiamat-local.1"
    namespace = (ISSUER, SUBJECT, "utopia-homes", "local-test")
    assert replay.consume(namespace, jti, int(time.time()) + 600) is False
    assert transport.calls == 0


def test_route_and_method_precede_malformed_framing_and_authentication() -> None:
    client, transport, _, _ = setup()
    wrong_route = client.request(
        "DELETE",
        "/wrong",
        content=b"x" * 1_048_577,
        headers={"Content-Length": "not-an-integer"},
    )
    wrong_method = client.request(
        "DELETE",
        "/execution/v1/inference",
        content=b"x" * 1_048_577,
        headers={"Content-Length": "not-an-integer"},
    )
    assert wrong_route.status_code == 404
    assert wrong_route.json()["error"]["code"] == "route_not_found"
    assert wrong_method.status_code == 405
    assert wrong_method.json()["error"]["code"] == "method_not_allowed"
    assert transport.calls == 0


def test_authentication_precedes_nonbinding_headers_and_contract_size() -> None:
    client, transport, private_key, _ = setup()
    raw = b"x" * 262_145
    invalid = headers(private_key, raw, scope="wrong")
    invalid["X-Request-ID"] = "not-a-uuid"
    invalid["Content-Type"] = "text/plain"
    response = client.post("/execution/v1/inference", content=raw, headers=invalid)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_failed"
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_nonbinding_header_order_precedes_media_and_contract_size() -> None:
    client, transport, private_key, _ = setup()
    raw = b"x" * 262_145
    invalid = headers(private_key, raw)
    invalid["X-Request-ID"] = "not-a-uuid"
    invalid["Content-Type"] = "text/plain"
    response = client.post("/execution/v1/inference", content=raw, headers=invalid)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert response.headers["x-stoin-execution-release"] == "tiamat-local.1"
    assert transport.calls == 0


def test_contract_size_precedes_raw_digest_and_json_validation() -> None:
    client, transport, private_key, _ = setup()
    raw = b"x" * 262_145
    wrong_hash = content_sha256(b"different")
    response = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, declared_hash=wrong_hash),
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"
    assert transport.calls == 0


def test_digest_precedes_json_and_profile_authorization() -> None:
    client, transport, private_key, _ = setup()
    raw = b"not-json"
    response = client.post(
        "/execution/v1/inference",
        content=raw,
        headers=headers(private_key, raw, declared_hash=content_sha256(b"different")),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_failed"
    assert "x-stoin-execution-release" not in response.headers
    assert transport.calls == 0


def test_non_json_numeric_constant_is_rejected_before_provider_dispatch() -> None:
    client, transport, private_key, _ = setup()
    raw = body().replace(b'"max_output_tokens":900', b'"max_output_tokens":NaN')
    response = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw)
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert transport.calls == 0
