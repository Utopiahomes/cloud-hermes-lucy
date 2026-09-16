from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import lucy.management_contract as management_module
from lucy.management_contract import (
    MANAGEMENT_BUNDLE_DIGEST,
    MANAGEMENT_BUNDLE_PATH,
    CapabilitiesResponse,
    ErrorResponse,
    HealthResponse,
    IdentityResponse,
    ManagementClient,
    ManagementContractError,
    ManagementJwtIssuer,
    ManagementObservation,
    VersionResponse,
    verify_management_bundle,
)


def _vectors(group: str) -> Iterator[dict[str, Any]]:
    for path in sorted((MANAGEMENT_BUNDLE_PATH / "vectors" / group).glob("*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


def _document(name: str) -> dict[str, Any]:
    path = MANAGEMENT_BUNDLE_PATH / "vectors" / "positive" / name
    return json.loads(path.read_text(encoding="utf-8"))["document"]


def _identity() -> IdentityResponse:
    return IdentityResponse.model_validate(_document("identity.pos.001.json"))


def _version() -> VersionResponse:
    return VersionResponse.model_validate(_document("version.pos.001.json"))


def _capabilities(state: str = "enabled") -> CapabilitiesResponse:
    value = _document("capabilities.pos.001.json")
    value["capabilities"][0]["state"] = state
    return CapabilitiesResponse.model_validate(value)


def test_pinned_bundle_digest_is_reproducible() -> None:
    assert verify_management_bundle() == MANAGEMENT_BUNDLE_DIGEST


def test_runtime_models_parse_every_positive_wire_vector() -> None:
    models = {
        "identity.response.schema.json": IdentityResponse,
        "health.response.schema.json": HealthResponse,
        "version.response.schema.json": VersionResponse,
        "capabilities.response.schema.json": CapabilitiesResponse,
        "error.response.schema.json": ErrorResponse,
    }
    parsed = 0
    for vector in _vectors("positive"):
        models[vector["schema"]].model_validate(vector["document"])
        parsed += 1
    assert parsed == 24


def test_runtime_models_ignore_additive_v1_members() -> None:
    value = _document("version.pos.001.json")
    value["future_optional_member"] = {"not": "authority"}
    value["management_provider"]["future_provider_member"] = True
    result = VersionResponse.model_validate(value)
    assert result.management_provider.release_id == value["management_provider"]["release_id"]
    assert "future_optional_member" not in result.model_dump()


def test_runtime_models_reject_explicit_null_for_absent_only_members() -> None:
    value = _document("health.pos.001.json")
    value["retry_after_seconds"] = None
    with pytest.raises(ValidationError, match="absent rather than null"):
        HealthResponse.model_validate(value)


def test_cross_resource_health_rules_reject_rc2_defects() -> None:
    unavailable_without_impaired = _document("health.pos.003.json")
    unavailable_without_impaired["degraded_capabilities"] = []
    with pytest.raises(ValidationError, match="zero-enabled reason"):
        HealthResponse.model_validate(unavailable_without_impaired)

    unknown_with_complete_impaired = _document("health.pos.001.json")
    unknown_with_complete_impaired["degraded_capabilities"] = ["guest.answer"]
    with pytest.raises(ValidationError, match="health status differs"):
        ManagementObservation(
            identity=_identity(),
            health=HealthResponse.model_validate(unknown_with_complete_impaired),
            version=_version(),
            capabilities=_capabilities(),
        )


def test_zero_enabled_state_is_unavailable_and_explicit() -> None:
    health = HealthResponse.model_validate(_document("health.pos.008.json"))
    observation = ManagementObservation(
        identity=_identity(),
        health=health,
        version=_version(),
        capabilities=_capabilities("disabled"),
    )
    assert observation.health.status == "unavailable"


def test_jwt_issuer_uses_exact_management_profile() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    issuer = ManagementJwtIssuer(private, key_id="management-reader-2026-09")
    now = datetime(2026, 9, 16, 3, 0, tzinfo=UTC)
    token = issuer.issue(now=now)
    header = jwt.get_unverified_header(token)
    assert header == {
        "alg": "EdDSA",
        "kid": "management-reader-2026-09",
        "typ": "JWT",
    }
    claims = jwt.decode(
        token,
        private.public_key(),
        algorithms=["EdDSA"],
        audience="stoin:management:utopia-homes-prime",
        issuer="stoin:control",
        options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
    )
    assert claims["sub"] == "stoin:service:control-management-reader"
    assert claims["scope"] == "management.read"
    assert claims["iat"] == int(now.timestamp())
    assert claims["nbf"] == claims["iat"]
    assert claims["exp"] == claims["iat"] + 300
    assert UUID(claims["jti"]).version == 4


class FakeResponse:
    def __init__(self, payload: dict[str, Any], request_id: str, status: int = 200) -> None:
        self.status = status
        self._raw = json.dumps(payload).encode()
        self._headers = {
            "Content-Type": "application/json",
            "X-Request-ID": request_id,
        }

    def read(self, maximum: int) -> bytes:
        return self._raw[:maximum]

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)


class FakeHttpsConnection:
    payloads: list[dict[str, Any] | tuple[int, dict[str, Any]]] = []
    requests: list[tuple[str, str, dict[str, str]]] = []

    def __init__(self, host: str, port: int, *, timeout: float, context: object) -> None:
        assert (host, port) == ("management.utopiahomes.test", 443)
        assert 0 < timeout <= 3.0
        assert context is not None
        self._request_id = ""

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self._request_id = headers["X-Request-ID"]
        type(self).requests.append((method, path, headers))

    def getresponse(self) -> FakeResponse:
        queued = type(self).payloads.pop(0)
        if isinstance(queued, tuple):
            status, payload = queued
            return FakeResponse(payload, self._request_id, status)
        return FakeResponse(queued, self._request_id)

    def close(self) -> None:
        pass


def test_https_client_reads_four_resources_and_sends_no_business_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpsConnection.payloads = [
        _document("identity.pos.001.json"),
        _document("health.pos.001.json"),
        _document("version.pos.001.json"),
        _document("capabilities.pos.001.json"),
    ]
    FakeHttpsConnection.requests = []
    monkeypatch.setattr(management_module.http.client, "HTTPSConnection", FakeHttpsConnection)
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    client = ManagementClient(
        "https://management.utopiahomes.test",
        ManagementJwtIssuer(private, key_id="management-reader"),
        sleeper=lambda _delay: None,
    )
    observation = client.observe()
    assert observation.identity.realm_id == "stoin:realm:utopia-homes"
    assert [request[1] for request in FakeHttpsConnection.requests] == [
        "/management/v1/identity",
        "/management/v1/health",
        "/management/v1/version",
        "/management/v1/capabilities",
    ]
    for method, _path, headers in FakeHttpsConnection.requests:
        assert method == "GET"
        assert set(headers) == {"Accept", "Authorization", "X-Request-ID"}
        assert headers["Authorization"].startswith("Bearer ")


def test_client_rejects_non_https_and_credentialed_endpoints() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    issuer = ManagementJwtIssuer(private, key_id="management-reader")
    for value in (
        "http://management.utopiahomes.test",
        "https://user:secret@management.utopiahomes.test",
        "https://management.utopiahomes.test/path",
        "https://management.utopiahomes.test?target=other",
    ):
        with pytest.raises(ValueError, match="endpoint configuration"):
            ManagementClient(value, issuer)


def test_client_retries_one_retryable_response_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeHttpsConnection.payloads = [
        (503, {}),
        _document("identity.pos.001.json"),
        _document("health.pos.001.json"),
        _document("version.pos.001.json"),
        _document("capabilities.pos.001.json"),
    ]
    FakeHttpsConnection.requests = []
    monkeypatch.setattr(management_module.http.client, "HTTPSConnection", FakeHttpsConnection)
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    client = ManagementClient(
        "https://management.utopiahomes.test",
        ManagementJwtIssuer(private, key_id="management-reader"),
        sleeper=lambda _delay: None,
    )
    assert client.observe().health.status == "unknown"
    assert [path for _method, path, _headers in FakeHttpsConnection.requests].count(
        "/management/v1/identity"
    ) == 2


def test_client_rejects_missing_echoed_request_id(monkeypatch: pytest.MonkeyPatch) -> None:
    class MissingEchoResponse(FakeResponse):
        def getheader(self, name: str) -> str | None:
            if name == "X-Request-ID":
                return None
            return super().getheader(name)

    class MissingEchoConnection(FakeHttpsConnection):
        def getresponse(self) -> FakeResponse:
            return MissingEchoResponse(_document("identity.pos.001.json"), self._request_id)

    monkeypatch.setattr(management_module.http.client, "HTTPSConnection", MissingEchoConnection)
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    client = ManagementClient(
        "https://management.utopiahomes.test",
        ManagementJwtIssuer(private, key_id="management-reader"),
        sleeper=lambda _delay: None,
    )
    with pytest.raises(ManagementContractError, match="response is invalid"):
        client.observe()


def test_bundle_verifier_fails_closed_on_changed_bytes(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "DIGEST.txt").write_text(MANAGEMENT_BUNDLE_DIGEST, encoding="ascii")
    (bundle / "changed.txt").write_text("different", encoding="utf-8")
    with pytest.raises(ManagementContractError, match="digest differs"):
        verify_management_bundle(bundle)
