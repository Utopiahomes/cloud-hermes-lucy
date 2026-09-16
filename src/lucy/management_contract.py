"""Control-side reader for Stoin Management Contract v1.0.

The provider conformance schemas are intentionally strict. Runtime parsing here is
forward-compatible within major version 1: required known fields are validated and
unknown response members are ignored.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MANAGEMENT_CONTRACT_VERSION = "1.0"
MANAGEMENT_BUNDLE_DIGEST = "c3bc25e4ae7708aba2581282d933ddd431d5ed5d0277a66477cdbe7ecc39fe33"
MANAGEMENT_BUNDLE_PATH = (
    Path(__file__).resolve().parents[2] / "contracts" / "stoin-management-v1-bundle"
)

_OBSERVED_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_CAPABILITY_ID = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$")
_CONTRACT_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_ARTIFACT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")


class ManagementContractError(RuntimeError):
    """Safe, content-free management boundary failure."""


class LenientModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class RuntimeResponse(LenientModel):

    contract_version: Literal["1.0"]
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_exact_utc(cls, value: str) -> str:
        if _OBSERVED_AT.fullmatch(value) is None:
            raise ValueError("observed_at must be whole-second UTC")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("observed_at must be a valid UTC timestamp") from exc
        return value


class IdentityResponse(RuntimeResponse):
    synth_id: Literal["stoin:synth:utopia-homes-prime"]
    realm_id: Literal["stoin:realm:utopia-homes"]
    synth_class: Literal["business-prime"]
    display_name: str = Field(min_length=1, max_length=100)


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ReasonCode(StrEnum):
    CAPACITY_LIMITED = "capacity_limited"
    CONFIGURATION_ERROR = "configuration_error"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    HEALTH_COVERAGE_LIMITED = "health_coverage_limited"
    MAINTENANCE = "maintenance"
    NO_ENABLED_CAPABILITIES = "no_enabled_capabilities"
    RELEASE_IN_PROGRESS = "release_in_progress"
    UNSPECIFIED = "unspecified"


class ErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORIZATION_DENIED = "authorization_denied"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    CONTRACT_NOT_SUPPORTED = "contract_not_supported"
    REQUEST_TOO_LARGE = "request_too_large"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
    MANAGEMENT_UNAVAILABLE = "management_unavailable"


class ErrorDetail(LenientModel):
    code: ErrorCode
    message: str = Field(min_length=1)
    correlation_id: UUID
    request_id: UUID | None = None
    retryable: bool

    @model_validator(mode="before")
    @classmethod
    def optional_request_id_is_absent_not_null(cls, value: Any) -> Any:
        if isinstance(value, dict) and value.get("request_id", ...) is None:
            raise ValueError("request_id must be absent rather than null")
        return value

    @model_validator(mode="after")
    def retryability_matches_code(self) -> ErrorDetail:
        retryable_codes = {
            ErrorCode.RATE_LIMITED,
            ErrorCode.INTERNAL_ERROR,
            ErrorCode.MANAGEMENT_UNAVAILABLE,
        }
        if self.retryable != (self.code in retryable_codes):
            raise ValueError("error retryability differs from code")
        if self.correlation_id.version != 4 or (
            self.request_id is not None and self.request_id.version != 4
        ):
            raise ValueError("error identifiers must be UUID v4")
        return self


class ErrorResponse(LenientModel):
    contract_version: Literal["1.0"]
    error: ErrorDetail


def _sorted_unique(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if tuple(sorted(values)) != values or len(set(values)) != len(values):
        raise ValueError(f"{label} must be a sorted set")
    return values


class HealthResponse(RuntimeResponse):
    status: HealthStatus
    management_provider_release_id: str = Field(min_length=1, max_length=128)
    degraded_capabilities: tuple[str, ...]
    reason_codes: tuple[ReasonCode, ...]
    retry_after_seconds: int | None = Field(default=None, ge=1, le=3600)

    @model_validator(mode="before")
    @classmethod
    def optional_retry_is_absent_not_null(cls, value: Any) -> Any:
        if isinstance(value, dict) and value.get("retry_after_seconds", ...) is None:
            raise ValueError("retry_after_seconds must be absent rather than null")
        return value

    @field_validator("management_provider_release_id")
    @classmethod
    def release_id_is_safe(cls, value: str) -> str:
        if _PRINTABLE_ASCII.fullmatch(value) is None:
            raise ValueError("release ID must be printable ASCII")
        return value

    @field_validator("degraded_capabilities")
    @classmethod
    def impaired_set_is_valid(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_CAPABILITY_ID.fullmatch(value) is None for value in values):
            raise ValueError("impaired capability ID is invalid")
        return _sorted_unique(values, "degraded_capabilities")

    @field_validator("reason_codes")
    @classmethod
    def reason_set_is_valid(cls, values: tuple[ReasonCode, ...]) -> tuple[ReasonCode, ...]:
        raw = tuple(value.value for value in values)
        _sorted_unique(raw, "reason_codes")
        if ReasonCode.UNSPECIFIED in values and len(values) != 1:
            raise ValueError("unspecified must be a stand-alone reason")
        return values

    @model_validator(mode="after")
    def local_status_rules_hold(self) -> HealthResponse:
        if self.status is HealthStatus.HEALTHY and self.degraded_capabilities:
            raise ValueError("healthy cannot name impaired capabilities")
        if self.status is HealthStatus.DEGRADED and not self.degraded_capabilities:
            raise ValueError("degraded must name an impaired capability")
        if self.status is HealthStatus.UNKNOWN and not self.reason_codes:
            raise ValueError("unknown must include a reason")
        has_none_enabled = ReasonCode.NO_ENABLED_CAPABILITIES in self.reason_codes
        if has_none_enabled and (
            self.status is not HealthStatus.UNAVAILABLE or self.degraded_capabilities
        ):
            raise ValueError("no-enabled state is internally inconsistent")
        if (
            self.status is HealthStatus.UNAVAILABLE
            and not self.degraded_capabilities
            and not has_none_enabled
        ):
            raise ValueError("unavailable empty impaired set lacks zero-enabled reason")
        return self


class ManagementProviderVersion(LenientModel):
    deployment_id: str = Field(min_length=1, max_length=160)
    runtime_id: str = Field(min_length=1, max_length=160)
    release_id: str = Field(min_length=1, max_length=128)
    software_version: str
    artifact_digest: str
    deployed_at: str

    @model_validator(mode="after")
    def fields_are_well_formed(self) -> ManagementProviderVersion:
        ascii_values = (self.deployment_id, self.runtime_id, self.release_id)
        if any(_PRINTABLE_ASCII.fullmatch(value) is None for value in ascii_values):
            raise ValueError("provider identifier must be printable ASCII")
        if _SEMVER.fullmatch(self.software_version) is None:
            raise ValueError("software version is invalid")
        if _ARTIFACT_DIGEST.fullmatch(self.artifact_digest) is None:
            raise ValueError("artifact digest is invalid")
        try:
            parsed = datetime.fromisoformat(self.deployed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("deployment timestamp is invalid") from exc
        if not self.deployed_at.endswith("Z") or parsed.tzinfo != UTC:
            raise ValueError("deployment timestamp must be UTC")
        return self


class ManagedSynthVersion(LenientModel):
    synth_id: Literal["stoin:synth:utopia-homes-prime"]
    observed_release_id: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="before")
    @classmethod
    def optional_release_is_absent_not_null(cls, value: Any) -> Any:
        if isinstance(value, dict) and value.get("observed_release_id", ...) is None:
            raise ValueError("observed_release_id must be absent rather than null")
        return value

    @field_validator("observed_release_id")
    @classmethod
    def observed_release_is_safe(cls, value: str | None) -> str | None:
        if value is not None and _PRINTABLE_ASCII.fullmatch(value) is None:
            raise ValueError("observed release ID must be printable ASCII")
        return value


class VersionResponse(RuntimeResponse):
    management_provider: ManagementProviderVersion
    managed_synth: ManagedSynthVersion
    supported_management_contracts: tuple[str, ...] = Field(min_length=1)

    @field_validator("supported_management_contracts")
    @classmethod
    def contracts_are_supported(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_CONTRACT_VERSION.fullmatch(value) is None for value in values):
            raise ValueError("supported contract version is invalid")
        _sorted_unique(values, "supported_management_contracts")
        if MANAGEMENT_CONTRACT_VERSION not in values:
            raise ValueError("management contract 1.0 is not supported")
        return values


class CapabilityState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class CapabilityResponse(LenientModel):
    capability_id: str
    contract_version: str
    state: CapabilityState
    business_contract_id: str | None = Field(default=None, min_length=1, max_length=160)

    @model_validator(mode="before")
    @classmethod
    def optional_contract_is_absent_not_null(cls, value: Any) -> Any:
        if isinstance(value, dict) and value.get("business_contract_id", ...) is None:
            raise ValueError("business_contract_id must be absent rather than null")
        return value

    @model_validator(mode="after")
    def fields_are_well_formed(self) -> CapabilityResponse:
        if _CAPABILITY_ID.fullmatch(self.capability_id) is None:
            raise ValueError("capability ID is invalid")
        if _CONTRACT_VERSION.fullmatch(self.contract_version) is None:
            raise ValueError("capability contract version is invalid")
        if self.business_contract_id is not None and _PRINTABLE_ASCII.fullmatch(
            self.business_contract_id
        ) is None:
            raise ValueError("business contract ID must be printable ASCII")
        return self


class CapabilitiesResponse(RuntimeResponse):
    capabilities: tuple[CapabilityResponse, ...]

    @field_validator("capabilities")
    @classmethod
    def capabilities_are_sorted_unique(
        cls, values: tuple[CapabilityResponse, ...]
    ) -> tuple[CapabilityResponse, ...]:
        ids = tuple(value.capability_id for value in values)
        _sorted_unique(ids, "capabilities")
        return values


class ManagementObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: IdentityResponse
    health: HealthResponse
    version: VersionResponse
    capabilities: CapabilitiesResponse

    @model_validator(mode="after")
    def cross_resource_invariants_hold(self) -> ManagementObservation:
        if (
            self.health.management_provider_release_id
            != self.version.management_provider.release_id
        ):
            raise ValueError("management provider release differs across resources")

        enabled = {
            capability.capability_id
            for capability in self.capabilities.capabilities
            if capability.state is CapabilityState.ENABLED
        }
        impaired = set(self.health.degraded_capabilities)
        if not impaired <= enabled:
            raise ValueError("impaired capability is not advertised and enabled")

        no_enabled = ReasonCode.NO_ENABLED_CAPABILITIES in self.health.reason_codes
        if no_enabled != (not enabled):
            raise ValueError("zero-enabled reason differs from capability advertisement")

        status = self.health.status
        legal = (
            (status is HealthStatus.HEALTHY and bool(enabled) and not impaired)
            or (
                status is HealthStatus.DEGRADED
                and bool(impaired)
                and impaired < enabled
            )
            or (
                status is HealthStatus.UNAVAILABLE
                and ((bool(enabled) and impaired == enabled) or (not enabled and not impaired))
            )
            or (
                status is HealthStatus.UNKNOWN
                and bool(enabled)
                and len(impaired) < len(enabled)
            )
        )
        if not legal:
            raise ValueError("health status differs from enabled and impaired sets")
        return self


class ManagementJwtIssuer:
    """Issue short-lived dedicated management-reader JWTs through PyJWT."""

    def __init__(self, private_key: Ed25519PrivateKey, *, key_id: str) -> None:
        if not key_id or len(key_id) > 160 or _PRINTABLE_ASCII.fullmatch(key_id) is None:
            raise ValueError("management JWT key ID is invalid")
        self._private_key = private_key
        self._key_id = key_id

    @classmethod
    def from_environment(cls) -> ManagementJwtIssuer:
        try:
            raw = base64.b64decode(
                os.environ["STOIN_MANAGEMENT_JWT_PRIVATE_KEY_B64"], validate=True
            )
            key_id = os.environ["STOIN_MANAGEMENT_JWT_KEY_ID"]
            if len(raw) != 32:
                raise ValueError
        except (KeyError, ValueError):
            raise ManagementContractError("management JWT configuration is invalid") from None
        return cls(Ed25519PrivateKey.from_private_bytes(raw), key_id=key_id)

    def issue(self, *, now: datetime | None = None) -> str:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("JWT issue time must be timezone-aware")
        issued_at = int(current.timestamp())
        claims = {
            "iss": "stoin:control",
            "sub": "stoin:service:control-management-reader",
            "aud": "stoin:management:utopia-homes-prime",
            "scope": "management.read",
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + 300,
            "jti": str(uuid4()),
        }
        return jwt.encode(
            claims,
            self._private_key,
            algorithm="EdDSA",
            headers={"kid": self._key_id, "typ": "JWT"},
        )


ResponseT = TypeVar("ResponseT", bound=RuntimeResponse)


class ManagementClient:
    """Bounded HTTPS reader for one provisioned Homes management adapter."""

    def __init__(
        self,
        base_url: str,
        issuer: ManagementJwtIssuer,
        *,
        timeout_seconds: float = 3.0,
        retry_delay_seconds: float = 0.05,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not 0 < timeout_seconds <= 3
            or not 0 <= retry_delay_seconds <= 0.25
        ):
            raise ValueError("management endpoint configuration is invalid")
        self._host = parsed.hostname
        self._port = parsed.port or 443
        self._issuer = issuer
        self._timeout = timeout_seconds
        self._retry_delay = retry_delay_seconds
        self._sleeper = sleeper

    def observe(self) -> ManagementObservation:
        return ManagementObservation(
            identity=self._get("identity", IdentityResponse, 65_536),
            health=self._get("health", HealthResponse, 16_384),
            version=self._get("version", VersionResponse, 65_536),
            capabilities=self._get("capabilities", CapabilitiesResponse, 65_536),
        )

    def _get(self, resource: str, model: type[ResponseT], maximum_bytes: int) -> ResponseT:
        request_id = uuid4()
        retryable_statuses = {429, 500, 503}
        deadline = time.monotonic() + self._timeout
        for attempt in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ManagementContractError("management provider is unavailable")
            connection = http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=remaining,
                context=ssl.create_default_context(),
            )
            try:
                connection.request(
                    "GET",
                    f"/management/v1/{resource}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._issuer.issue()}",
                        "X-Request-ID": str(request_id),
                    },
                )
                response = connection.getresponse()
                raw = response.read(maximum_bytes + 1)
                echoed_request_id = response.getheader("X-Request-ID")
                correlation_id = response.getheader("X-Correlation-ID")
                content_type = response.getheader("Content-Type")
            except (OSError, http.client.HTTPException):
                if attempt == 0:
                    self._pause_before_retry(deadline)
                    continue
                raise ManagementContractError("management provider is unavailable") from None
            finally:
                connection.close()

            if response.status in retryable_statuses and attempt == 0:
                self._pause_before_retry(deadline)
                continue
            if response.status != 200:
                try:
                    error = ErrorResponse.model_validate(json.loads(raw))
                    if (
                        error.error.request_id != request_id
                        or echoed_request_id != str(request_id)
                        or correlation_id != str(error.error.correlation_id)
                    ):
                        raise ValueError
                except (json.JSONDecodeError, UnicodeError, ValidationError, ValueError):
                    raise ManagementContractError(
                        "management provider error response is invalid"
                    ) from None
                raise ManagementContractError("management provider rejected the request")
            if (
                len(raw) > maximum_bytes
                or echoed_request_id != str(request_id)
                or content_type is None
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
            ):
                raise ManagementContractError("management provider response is invalid")
            try:
                value: Any = json.loads(raw)
                return model.model_validate(value)
            except (json.JSONDecodeError, UnicodeError, ValidationError):
                raise ManagementContractError("management provider response is invalid") from None
        raise AssertionError("management retry loop did not return")

    def _pause_before_retry(self, deadline: float) -> None:
        if self._retry_delay >= deadline - time.monotonic():
            raise ManagementContractError("management provider is unavailable")
        self._sleeper(self._retry_delay)


def verify_management_bundle(path: Path = MANAGEMENT_BUNDLE_PATH) -> str:
    """Independently reproduce and enforce the pinned canonical artifact digest."""

    if not path.is_dir():
        raise ManagementContractError("management contract bundle is missing")
    rows: list[bytes] = []
    for file in sorted(
        (
            candidate
            for candidate in path.rglob("*")
            if candidate.is_file() and candidate.name not in {"MANIFEST.json", "DIGEST.txt"}
        ),
        key=lambda candidate: candidate.relative_to(path).as_posix().encode(),
    ):
        relative = file.relative_to(path).as_posix()
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        rows.append(f"{digest}  {relative}\n".encode())
    actual = hashlib.sha256(b"".join(rows)).hexdigest()
    try:
        declared = (path / "DIGEST.txt").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise ManagementContractError("management contract digest is unreadable") from None
    if declared.removeprefix("sha256:") != actual or actual != MANAGEMENT_BUNDLE_DIGEST:
        raise ManagementContractError("management contract bundle digest differs")
    return actual
