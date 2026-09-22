"""A synthetic release-signing root for one disposable environment.

The bundle's signed vectors are pinned to a single environment and caller, so a proof that runs in
its own throwaway environment needs its own root. This mints one: a root key, a release key the
root's inventory authorizes for exactly the subjects the case uses, and real signatures over both.
Releases then go through the authority store's ordinary path - verified, staged, activated - so
the serving side verifies genuinely signed bytes, not rows written around the verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from lucy.shared_execution.canonical import canonical_json_bytes
from lucy.shared_execution.postgres_authority import AuthorityScope, PostgresSignedAuthorityStore
from lucy.shared_execution.signed_releases import (
    INVENTORY_TYP,
    RELEASE_TYP,
    verify_release,
    verify_trust_inventory,
)

AUTHORITY_ISSUER = "stoin-control"
ROOT_KEY_ID = "tiamat-trust-root-synthetic-1"
RELEASE_KEY_ID = "release-key-synthetic-1"


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _segment(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _compact(payload: dict[str, Any], *, kid: str, typ: str, key: Ed25519PrivateKey) -> bytes:
    header = json.dumps({"alg": "EdDSA", "kid": kid, "typ": typ}, separators=(",", ":"))
    signing = _segment(header.encode()) + b"." + _segment(json.dumps(payload).encode())
    return signing + b"." + _segment(key.sign(signing))


@dataclass
class SyntheticReleaseTrust:
    environment: str
    caller_id: str
    realm: str
    root: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    release_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def root_public_key(self) -> Ed25519PublicKey:
        return self.root.public_key()

    @property
    def scope(self) -> AuthorityScope:
        return AuthorityScope(self.environment, AUTHORITY_ISSUER, self.caller_id, self.realm)

    def inventory_jws(self, subjects: list[tuple[str, str]]) -> bytes:
        now = datetime.now(UTC)
        public = self.release_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _compact(
            {
                "format_version": "1",
                "inventory_generation": 1,
                "previous_inventory_digest": None,
                "issued_at": _stamp(now - timedelta(minutes=5)),
                "environment": self.environment,
                "root_key_id": ROOT_KEY_ID,
                "keys": [
                    {
                        "kid": RELEASE_KEY_ID,
                        "issuer": AUTHORITY_ISSUER,
                        "environment": self.environment,
                        "purpose": "policy_notary_v13",
                        "use": "tiamat-signed-release",
                        "algorithm": "EdDSA",
                        "public_key_b64": base64.b64encode(public).decode(),
                        "status": "active",
                        "valid_from": _stamp(now - timedelta(days=1)),
                        "issuance_not_after": _stamp(now + timedelta(days=1)),
                        "verify_not_after": _stamp(now + timedelta(days=2)),
                        "revoked_at": None,
                        "active_release_policy": "invalidate_immediately",
                        "authorized_scopes": [
                            {
                                "caller_id": self.caller_id,
                                "realm": self.realm,
                                "release_type": release_type,
                                "subject_id": subject_id,
                            }
                            for release_type, subject_id in subjects
                        ],
                    }
                ],
            },
            kid=ROOT_KEY_ID,
            typ=INVENTORY_TYP,
            key=self.root,
        )

    def release_jws(
        self,
        release_type: str,
        subject_id: str,
        release_id: str,
        content: dict[str, Any],
        *,
        sequence: int = 1,
        predecessor: str | None = None,
    ) -> bytes:
        now = datetime.now(UTC)
        return _compact(
            {
                "format_version": "1",
                "release_id": release_id,
                "subject_id": subject_id,
                "issuer": AUTHORITY_ISSUER,
                "environment": self.environment,
                "caller_id": self.caller_id,
                "realm": self.realm,
                "issued_at": _stamp(now - timedelta(minutes=5)),
                "not_before": _stamp(now - timedelta(hours=1)),
                "not_after": _stamp(now + timedelta(days=1)),
                "sequence": sequence,
                "predecessor_release_id": predecessor,
                "content_digest": hashlib.sha256(canonical_json_bytes(content)).hexdigest(),
                "release_type": release_type,
                "content": content,
            },
            kid=RELEASE_KEY_ID,
            typ=RELEASE_TYP,
            key=self.release_key,
        )


@dataclass(frozen=True)
class SignedProfile:
    profile_id: str
    release_id: str
    policy_id: str
    policy_release_id: str
    provider_route_id: str
    rate_release_id: str
    maximum_output_tokens: int = 900
    maximum_reservable_microusd: int = 2_000
    timeout_ceiling_ms: int = 15_000
    approved_route_ids: tuple[str, ...] = ()


def install_signed_authority(
    trust: SyntheticReleaseTrust,
    manager_url: str,
    recovery_url: str,
    profile: SignedProfile,
) -> None:
    """Sign and activate the inventory, the profile, its policy and the partition's grant.

    The grant reuses the partition's seeded grant row, whose release ID the signed grant takes,
    because activating a grant projects that row onto the partition.
    """

    grant = _seeded_grant(recovery_url, trust)
    subjects = [
        ("execution_profile", profile.profile_id),
        ("privacy_policy", profile.policy_id),
        ("spending_grant", grant["partition_id"]),
    ]
    store = PostgresSignedAuthorityStore(manager_url)
    inventory_jws = trust.inventory_jws(subjects)
    inventory = verify_trust_inventory(
        inventory_jws,
        root_key_id=ROOT_KEY_ID,
        root_public_key=trust.root_public_key,
        environment=trust.environment,
    )
    store.stage_inventory(inventory_jws, inventory, hashlib.sha256(inventory_jws).hexdigest())
    store.activate_inventory(trust.environment, 1)

    releases = [
        (
            "privacy_policy",
            profile.policy_id,
            profile.policy_release_id,
            {
                "policy_id": profile.policy_id,
                "approved_provider_route_ids": list(
                    profile.approved_route_ids or (profile.provider_route_id,)
                ),
                "required_provider_privacy": ["zero_data_retention", "no_training"],
                "data_collection": "denied",
                "training": "denied",
                "fallback_allowed": False,
                "allowed_regions": ["us"],
                "retention_ceiling_seconds": 0,
                "eligibility_generation": 1,
            },
        ),
        (
            "execution_profile",
            profile.profile_id,
            profile.release_id,
            {
                "profile_id": profile.profile_id,
                "provider_route_id": profile.provider_route_id,
                "model_id": "synthetic-model",
                "allowed_output_modes": ["text"],
                "maximum_input_tokens": 8_000,
                "maximum_output_tokens": profile.maximum_output_tokens,
                "maximum_context_tokens": 16_000,
                "timeout_ceiling_ms": profile.timeout_ceiling_ms,
                "privacy_policy_release_id": profile.policy_release_id,
                "data_collection": "denied",
                "training": "denied",
                "zero_data_retention_required": True,
                "fallback_allowed": False,
                "rate_release_id": profile.rate_release_id,
                "rates": {
                    "input_per_million_microusd": 100_000,
                    "output_per_million_microusd": 400_000,
                    "reasoning_per_million_microusd": 400_000,
                    "per_request_microusd": 0,
                },
                "maximum_reservable_microusd": profile.maximum_reservable_microusd,
            },
        ),
        (
            "spending_grant",
            grant["partition_id"],
            grant["release_id"],
            {
                "partition_id": grant["partition_id"],
                "budget_period_id": grant["budget_period_id"],
                "period_start": _stamp(grant["period_start"]),
                "period_end": _stamp(grant["period_end"]),
                "allowance_microusd": grant["allowance_microusd"],
                "maximum_concurrency": grant["maximum_concurrency"],
                "largest_per_call_microusd": grant["largest_per_call_microusd"],
                "contingency_reserve_microusd": grant["contingency_reserve_microusd"],
            },
        ),
    ]
    for release_type, subject_id, release_id, content in releases:
        verified = verify_release(
            trust.release_jws(release_type, subject_id, release_id, content),
            inventory=inventory,
            expected_issuer=AUTHORITY_ISSUER,
            expected_environment=trust.environment,
            expected_caller_id=trust.caller_id,
            expected_realm=trust.realm,
            now=datetime.now(UTC),
        )
        store.stage_release(verified, RELEASE_KEY_ID)
        store.activate_release(trust.scope, release_type, subject_id, release_id)


def _seeded_grant(recovery_url: str, trust: SyntheticReleaseTrust) -> dict[str, Any]:
    with psycopg.connect(recovery_url, row_factory=psycopg.rows.dict_row) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (trust.environment,)
        )
        recovery.execute("SELECT set_config('tiamat.caller_id', %s, false)", (trust.caller_id,))
        recovery.execute("SELECT set_config('tiamat.realm', %s, false)", (trust.realm,))
        row = recovery.execute(
            """
            SELECT g.release_id, g.partition_id, g.budget_period_id, g.period_start,
                   g.period_end, g.allowance_microusd, g.maximum_concurrency,
                   g.largest_per_call_microusd, g.contingency_reserve_microusd
            FROM tiamat.spending_partitions p
            JOIN tiamat.grant_releases g ON g.release_id = p.active_grant_release_id
            WHERE p.environment = %s AND p.caller_id = %s AND p.realm = %s
            """,
            (trust.environment, trust.caller_id, trust.realm),
        ).fetchone()
    assert row is not None, "the environment has no seeded grant"
    return dict(row)
