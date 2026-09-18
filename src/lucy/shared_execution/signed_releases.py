"""Fail-closed verification for Tiamat signed release RC1 compact JWS objects."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from lucy.shared_execution.canonical import canonical_json_bytes

MAX_COMPACT_JWS_BYTES = 131_072
RELEASE_TYP = "stoin-signed-release+jws"
INVENTORY_TYP = "stoin-release-trust-inventory+jws"


class SignedReleaseRejected(ValueError):
    """A release or inventory failed a fail-closed RC1 check."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Rates(StrictModel):
    input_per_million_microusd: int = Field(ge=0)
    output_per_million_microusd: int = Field(ge=0)
    reasoning_per_million_microusd: int = Field(ge=0)
    per_request_microusd: int = Field(ge=0)


class ExecutionProfileContent(StrictModel):
    profile_id: str
    provider_route_id: str
    model_id: str
    allowed_output_modes: list[Literal["text", "json_schema"]] = Field(min_length=1)
    maximum_input_tokens: int = Field(ge=1, le=10_000_000)
    maximum_output_tokens: int = Field(ge=1, le=1_000_000)
    maximum_context_tokens: int = Field(ge=1, le=10_000_000)
    timeout_ceiling_ms: int = Field(ge=1, le=300_000)
    privacy_policy_release_id: str
    data_collection: Literal["denied"]
    training: Literal["denied"]
    zero_data_retention_required: Literal[True]
    fallback_allowed: Literal[False]
    rate_release_id: str
    rates: Rates
    maximum_reservable_microusd: int = Field(ge=1)


class PrivacyPolicyContent(StrictModel):
    policy_id: str
    approved_provider_route_ids: list[str] = Field(min_length=1)
    required_provider_privacy: list[
        Literal["zero_data_retention", "no_training", "no_data_collection"]
    ] = Field(min_length=1)
    data_collection: Literal["denied"]
    training: Literal["denied"]
    fallback_allowed: Literal[False]
    allowed_regions: list[str] = Field(min_length=1)
    retention_ceiling_seconds: int = Field(ge=0, le=86_400)
    eligibility_generation: int = Field(ge=1)


class SpendingGrantContent(StrictModel):
    partition_id: str
    budget_period_id: str
    period_start: str
    period_end: str
    allowance_microusd: int = Field(ge=1)
    maximum_concurrency: int = Field(ge=1, le=10_000)
    largest_per_call_microusd: int = Field(ge=1)
    contingency_reserve_microusd: int = Field(ge=1)


class RevocationContent(StrictModel):
    target_type: Literal["release"]
    target_release_type: Literal["execution_profile", "privacy_policy", "spending_grant"]
    target_release_id: str
    reason_code: str
    effective_at: str
    eligibility_generation: int = Field(ge=1)


class ReleaseBase(StrictModel):
    format_version: Literal["1"]
    release_id: str
    subject_id: str
    issuer: str
    environment: str
    caller_id: str
    realm: str
    issued_at: str
    not_before: str
    not_after: str
    sequence: int = Field(ge=1, le=9_007_199_254_740_991)
    predecessor_release_id: str | None
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExecutionProfileRelease(ReleaseBase):
    release_type: Literal["execution_profile"]
    content: ExecutionProfileContent


class PrivacyPolicyRelease(ReleaseBase):
    release_type: Literal["privacy_policy"]
    content: PrivacyPolicyContent


class SpendingGrantRelease(ReleaseBase):
    release_type: Literal["spending_grant"]
    content: SpendingGrantContent


class RevocationRelease(ReleaseBase):
    release_type: Literal["revocation"]
    content: RevocationContent


Release = Annotated[
    ExecutionProfileRelease | PrivacyPolicyRelease | SpendingGrantRelease | RevocationRelease,
    Field(discriminator="release_type"),
]
RELEASE_ADAPTER: TypeAdapter[Release] = TypeAdapter(Release)


class AuthorizedScope(StrictModel):
    caller_id: str
    realm: str
    release_type: Literal["execution_profile", "privacy_policy", "spending_grant", "revocation"]
    subject_id: str


class InventoryKey(StrictModel):
    kid: str
    issuer: str
    environment: str
    purpose: Literal["policy_notary_v13"]
    use: Literal["tiamat-signed-release"]
    algorithm: Literal["EdDSA"]
    public_key_b64: str
    status: Literal["staged", "active", "retired", "revoked"]
    valid_from: str
    issuance_not_after: str
    verify_not_after: str
    revoked_at: str | None
    active_release_policy: Literal["invalidate_immediately", "honor_active_until_expiry"]
    authorized_scopes: list[AuthorizedScope] = Field(min_length=1)


class TrustInventory(StrictModel):
    format_version: Literal["1"]
    inventory_generation: int = Field(ge=1)
    previous_inventory_digest: str | None
    issued_at: str
    environment: str
    root_key_id: str
    keys: list[InventoryKey] = Field(min_length=1)


@dataclass(frozen=True)
class VerifiedRelease:
    payload: Release
    exact_jws: bytes
    jws_sha256: str


@dataclass(frozen=True)
class AuthorizedExecutionProfile:
    profile_id: str
    profile_release_id: str
    privacy_policy_release_id: str
    spending_grant_release_id: str
    partition_id: str
    allowed_output_modes: frozenset[Literal["text", "json_schema"]]
    maximum_output_tokens: int
    maximum_reservable_microusd: int


class ActiveAuthorityReader(Protocol):
    def load_active_inventory_jws(self, environment: str) -> bytes: ...

    def load_active_jws(self, scope: Any, release_type: str, subject_id: str) -> bytes: ...

    def load_active_jws_by_release_id(
        self, scope: Any, release_type: str, release_id: str
    ) -> bytes: ...


def load_authorized_profile(
    reader: ActiveAuthorityReader,
    *,
    scope: Any,
    root_key_id: str,
    root_public_key: Ed25519PublicKey,
    issuer: str,
    environment: str,
    caller_id: str,
    realm: str,
    profile_id: str,
    partition_id: str,
    now: datetime,
) -> AuthorizedExecutionProfile:
    """Load, reverify, and resolve the complete active authority set at cold start."""

    inventory = verify_trust_inventory(
        reader.load_active_inventory_jws(environment),
        root_key_id=root_key_id,
        root_public_key=root_public_key,
        environment=environment,
    )

    def verified(exact: bytes) -> VerifiedRelease:
        return verify_release(
            exact,
            inventory=inventory,
            expected_issuer=issuer,
            expected_environment=environment,
            expected_caller_id=caller_id,
            expected_realm=realm,
            now=now,
        )

    profile = verified(reader.load_active_jws(scope, "execution_profile", profile_id))
    if not isinstance(profile.payload, ExecutionProfileRelease):
        raise SignedReleaseRejected("execution_profile_unavailable")
    policy = verified(
        reader.load_active_jws_by_release_id(
            scope,
            "privacy_policy",
            profile.payload.content.privacy_policy_release_id,
        )
    )
    grant = verified(reader.load_active_jws(scope, "spending_grant", partition_id))
    return authorize_release_set(
        [profile, policy, grant],
        profile_id=profile_id,
        now=now,
    )


def authorize_release_set(
    releases: list[VerifiedRelease], *, profile_id: str, now: datetime
) -> AuthorizedExecutionProfile:
    """Resolve one complete current profile/policy/grant set or fail closed."""

    profiles = [
        item.payload
        for item in releases
        if isinstance(item.payload, ExecutionProfileRelease)
        and item.payload.content.profile_id == profile_id
    ]
    policies = [item.payload for item in releases if isinstance(item.payload, PrivacyPolicyRelease)]
    grants = [item.payload for item in releases if isinstance(item.payload, SpendingGrantRelease)]
    if len(profiles) != 1 or not policies or len(grants) != 1:
        raise SignedReleaseRejected("complete_release_set_unavailable")
    profile = profiles[0]
    policy_matches = [
        item for item in policies if item.release_id == profile.content.privacy_policy_release_id
    ]
    if len(policy_matches) != 1:
        raise SignedReleaseRejected("privacy_policy_unavailable")
    policy = policy_matches[0]
    grant = grants[0]
    current = now.astimezone(UTC)
    if not (
        _parse_time(grant.content.period_start) <= current < _parse_time(grant.content.period_end)
    ):
        raise SignedReleaseRejected("budget_period_unavailable")
    if profile.content.provider_route_id not in policy.content.approved_provider_route_ids:
        raise SignedReleaseRejected("privacy_route_unavailable")
    if profile.content.maximum_reservable_microusd > grant.content.largest_per_call_microusd:
        raise SignedReleaseRejected("spending_authority_insufficient")
    if len(set(profile.content.allowed_output_modes)) != len(profile.content.allowed_output_modes):
        raise SignedReleaseRejected("profile_modes_invalid")
    return AuthorizedExecutionProfile(
        profile_id=profile.content.profile_id,
        profile_release_id=profile.release_id,
        privacy_policy_release_id=policy.release_id,
        spending_grant_release_id=grant.release_id,
        partition_id=grant.content.partition_id,
        allowed_output_modes=frozenset(profile.content.allowed_output_modes),
        maximum_output_tokens=profile.content.maximum_output_tokens,
        maximum_reservable_microusd=profile.content.maximum_reservable_microusd,
    )


def verify_trust_inventory(
    exact_jws: bytes,
    *,
    root_key_id: str,
    root_public_key: Ed25519PublicKey,
    environment: str,
) -> TrustInventory:
    payload = _verify_compact(exact_jws, root_key_id, root_public_key, INVENTORY_TYP)
    try:
        inventory = TrustInventory.model_validate(payload)
    except ValidationError as exc:
        raise SignedReleaseRejected("inventory_schema_invalid") from exc
    if inventory.root_key_id != root_key_id or inventory.environment != environment:
        raise SignedReleaseRejected("inventory_scope_invalid")
    if len({key.kid for key in inventory.keys}) != len(inventory.keys):
        raise SignedReleaseRejected("inventory_duplicate_kid")
    for key in inventory.keys:
        _parse_time(key.valid_from)
        _parse_time(key.issuance_not_after)
        _parse_time(key.verify_not_after)
        if (key.status == "revoked") != (key.revoked_at is not None):
            raise SignedReleaseRejected("inventory_revocation_invalid")
    return inventory


def verify_release(
    exact_jws: bytes,
    *,
    inventory: TrustInventory | None,
    expected_issuer: str,
    expected_environment: str,
    expected_caller_id: str,
    expected_realm: str,
    now: datetime,
) -> VerifiedRelease:
    if inventory is None:
        raise SignedReleaseRejected("trust_inventory_unavailable")
    if len(exact_jws) > MAX_COMPACT_JWS_BYTES or len(exact_jws.split(b".")) != 3:
        raise SignedReleaseRejected("compact_invalid")
    header = _decode_segment(exact_jws.split(b".")[0])
    kid = header.get("kid")
    key_record = next((item for item in inventory.keys if item.kid == kid), None)
    if key_record is None:
        raise SignedReleaseRejected("unknown_kid")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(key_record.public_key_b64))
    except (ValueError, TypeError) as exc:
        raise SignedReleaseRejected("key_invalid") from exc
    payload_raw = _verify_compact(exact_jws, key_record.kid, public_key, RELEASE_TYP)
    try:
        release = RELEASE_ADAPTER.validate_python(payload_raw)
    except ValidationError as exc:
        raise SignedReleaseRejected("release_schema_invalid") from exc

    current = now.astimezone(UTC)
    issued = _parse_time(release.issued_at)
    not_before = _parse_time(release.not_before)
    not_after = _parse_time(release.not_after)
    key_from = _parse_time(key_record.valid_from)
    issue_until = _parse_time(key_record.issuance_not_after)
    verify_until = _parse_time(key_record.verify_not_after)
    if key_record.status == "revoked" or current > verify_until:
        raise SignedReleaseRejected("key_not_usable")
    if not (key_from <= issued <= issue_until) or not (not_before <= current < not_after):
        raise SignedReleaseRejected("release_not_current")
    if (
        release.issuer != expected_issuer
        or release.environment != expected_environment
        or release.caller_id != expected_caller_id
        or release.realm != expected_realm
        or key_record.issuer != expected_issuer
        or key_record.environment != expected_environment
    ):
        raise SignedReleaseRejected("release_scope_invalid")
    scope = (release.caller_id, release.realm, release.release_type, release.subject_id)
    allowed = {
        (item.caller_id, item.realm, item.release_type, item.subject_id)
        for item in key_record.authorized_scopes
    }
    if scope not in allowed:
        raise SignedReleaseRejected("release_scope_invalid")
    if (
        hashlib.sha256(canonical_json_bytes(payload_raw["content"])).hexdigest()
        != release.content_digest
    ):
        raise SignedReleaseRejected("content_digest_mismatch")
    _verify_type_invariants(release)
    return VerifiedRelease(release, exact_jws, hashlib.sha256(exact_jws).hexdigest())


def _verify_type_invariants(release: Release) -> None:
    if (
        isinstance(release, ExecutionProfileRelease)
        and release.subject_id != release.content.profile_id
    ):
        raise SignedReleaseRejected("subject_binding_invalid")
    if (
        isinstance(release, PrivacyPolicyRelease)
        and release.subject_id != release.content.policy_id
    ):
        raise SignedReleaseRejected("subject_binding_invalid")
    if isinstance(release, SpendingGrantRelease):
        if release.subject_id != release.content.partition_id:
            raise SignedReleaseRejected("subject_binding_invalid")
        required = (
            2 * release.content.maximum_concurrency * release.content.largest_per_call_microusd
        )
        if release.content.contingency_reserve_microusd < required:
            raise SignedReleaseRejected("contingency_invalid")


def _verify_compact(
    exact_jws: bytes,
    expected_kid: str,
    public_key: Ed25519PublicKey,
    expected_typ: str,
) -> dict[str, Any]:
    if len(exact_jws) > MAX_COMPACT_JWS_BYTES:
        raise SignedReleaseRejected("jws_too_large")
    parts = exact_jws.split(b".")
    if len(parts) != 3 or any(b"=" in part for part in parts):
        raise SignedReleaseRejected("compact_invalid")
    header = _decode_segment(parts[0])
    if set(header) != {"alg", "kid", "typ"} or header != {
        "alg": "EdDSA",
        "kid": expected_kid,
        "typ": expected_typ,
    }:
        raise SignedReleaseRejected("header_invalid")
    try:
        signature = _base64url_decode(parts[2])
        public_key.verify(signature, parts[0] + b"." + parts[1])
    except (InvalidSignature, ValueError) as exc:
        raise SignedReleaseRejected("signature_invalid") from exc
    return _decode_segment(parts[1])


def _decode_segment(segment: bytes) -> dict[str, Any]:
    try:
        raw = _base64url_decode(segment)
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SignedReleaseRejected("compact_invalid") from exc
    if not isinstance(value, dict):
        raise SignedReleaseRejected("compact_invalid")
    return value


def _base64url_decode(value: bytes) -> bytes:
    return base64.b64decode(value + b"=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _parse_time(value: str) -> datetime:
    try:
        if len(value) != 20 or not value.endswith("Z"):
            raise ValueError
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SignedReleaseRejected("timestamp_invalid") from exc
