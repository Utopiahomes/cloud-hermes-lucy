from __future__ import annotations

import json
import time
from typing import Any
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lucy.shared_execution.api import ApiRelease, create_shared_execution_app
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
from lucy.shared_execution.wire import ExecutionRequest

ISSUER = "https://homes.internal"
SUBJECT = "stoin:synth:utopia-homes-prime"
PROFILE = "utopia-homes.public-answer.generate.v1"
KEY_ID = "homes-prime-local-1"


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


def setup() -> tuple[TestClient, FakeTransport, Ed25519PrivateKey, InMemoryJtiReplayStore]:
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
    transport = FakeTransport()
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
    response = client.post(
        "/execution/v1/inference", content=raw, headers=request_headers
    )
    assert response.status_code == 200
    assert response.json()["request_id"] == request_headers["X-Request-ID"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-stoin-execution-release"] == "tiamat-local.1"
    assert response.headers["x-stoin-execution-policy-release"] == "profiles-local.1"
    assert "set-cookie" not in response.headers
    assert transport.calls == 1


def test_fresh_jwt_replays_same_operation_without_second_provider_call() -> None:
    client, transport, private_key, _ = setup()
    raw = body()
    key = uuid4()
    first = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw, key=key)
    )
    second_headers = headers(private_key, raw, key=key)
    second = client.post(
        "/execution/v1/inference", content=raw, headers=second_headers
    )
    assert first.status_code == second.status_code == 200
    assert second.json()["execution_id"] == first.json()["execution_id"]
    assert second.json()["replayed"] is True
    assert second.json()["request_id"] == second_headers["X-Request-ID"]
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
    invalid_response = client.post(
        "/execution/v1/inference", content=raw, headers=invalid
    )
    valid_response = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw)
    )
    assert invalid_response.status_code == 401
    assert valid_response.status_code == 503
    assert valid_response.json()["error"]["code"] == "authentication_state_unavailable"
    assert "x-stoin-execution-release" not in valid_response.headers
    assert transport.calls == 0


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
    response = client.post(
        "/execution/v1/inference", content=raw, headers=request_headers
    )
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
    assert "x-stoin-execution-release" not in response.headers


def test_non_json_numeric_constant_is_rejected_before_provider_dispatch() -> None:
    client, transport, private_key, _ = setup()
    raw = body().replace(b'"max_output_tokens":900', b'"max_output_tokens":NaN')
    response = client.post(
        "/execution/v1/inference", content=raw, headers=headers(private_key, raw)
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert transport.calls == 0
