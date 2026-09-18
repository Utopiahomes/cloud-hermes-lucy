from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucy.shared_execution.signed_releases import (
    SignedReleaseRejected,
    authorize_release_set,
    load_authorized_profile,
    verify_release,
    verify_trust_inventory,
)

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "contracts" / "tiamat-signed-release-v1-rc1-bundle"
NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)


def vector(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def root_key() -> Ed25519PublicKey:
    keys = vector(BUNDLE / "test-keys.json")
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(str(keys["root_public_key_b64"])))


def inventory():
    item = vector(BUNDLE / "vectors" / "positive" / "inventory.pos.bootstrap.json")
    return verify_trust_inventory(
        str(item["compact_jws"]).encode(),
        root_key_id="tiamat-trust-root-staging-1",
        root_public_key=root_key(),
        environment="staging",
    )


def verified_release(name: str):
    item = vector(BUNDLE / "vectors" / "positive" / f"release.pos.{name}.json")
    return verify_release(
        str(item["compact_jws"]).encode(),
        inventory=inventory(),
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=NOW,
    )


def test_root_signed_inventory_loads_and_release_exact_bytes_are_preserved() -> None:
    item = vector(BUNDLE / "vectors" / "positive" / "release.pos.execution-profile.json")
    exact = str(item["compact_jws"]).encode()
    verified = verify_release(
        exact,
        inventory=inventory(),
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=NOW,
    )
    assert verified.exact_jws == exact
    assert verified.payload.release_id == "profiles-2026-09-17.1"
    assert len(verified.jws_sha256) == 64


@pytest.mark.parametrize(
    "filename",
    [
        "release.neg.bad-signature.json",
        "release.neg.content-digest.json",
        "release.neg.contingency.json",
        "release.neg.duplicate-header.json",
        "release.neg.duplicate-json-member.json",
        "release.neg.float.json",
        "release.neg.invalid-utf8.json",
        "release.neg.key-revocation.json",
        "release.neg.malformed.json",
        "release.neg.oversized.json",
        "release.neg.padding.json",
        "release.neg.payload-reserialized.json",
        "release.neg.scope.json",
        "release.neg.subject-binding.json",
        "release.neg.unknown-header.json",
        "release.neg.unknown-kid.json",
        "release.neg.unknown-member.json",
        "release.neg.unknown-release-type.json",
        "release.neg.unknown-version.json",
        "release.neg.wrong-alg.json",
    ],
)
def test_negative_compact_release_vectors_fail_closed(filename: str) -> None:
    item = vector(BUNDLE / "vectors" / "negative" / filename)
    with pytest.raises(SignedReleaseRejected):
        verify_release(
            str(item["compact_jws"]).encode(),
            inventory=inventory(),
            expected_issuer="stoin-control",
            expected_environment="staging",
            expected_caller_id="stoin:synth:utopia-homes",
            expected_realm="utopia-homes",
            now=NOW,
        )


def test_release_key_cannot_sign_the_trust_inventory() -> None:
    item = vector(BUNDLE / "vectors" / "negative" / "inventory.neg.release-key-signed.json")
    with pytest.raises(SignedReleaseRejected):
        verify_trust_inventory(
            str(item["compact_jws"]).encode(),
            root_key_id="tiamat-trust-root-staging-1",
            root_public_key=root_key(),
            environment="staging",
        )


def test_no_inventory_means_no_release_authority() -> None:
    item = vector(BUNDLE / "vectors" / "positive" / "release.pos.execution-profile.json")
    with pytest.raises(SignedReleaseRejected, match="trust_inventory_unavailable"):
        verify_release(
            str(item["compact_jws"]).encode(),
            inventory=None,
            expected_issuer="stoin-control",
            expected_environment="staging",
            expected_caller_id="stoin:synth:utopia-homes",
            expected_realm="utopia-homes",
            now=NOW,
        )


def test_complete_profile_policy_and_grant_resolve_execution_authority() -> None:
    authority = authorize_release_set(
        [
            verified_release("execution-profile"),
            verified_release("privacy-policy"),
            verified_release("spending-grant"),
        ],
        profile_id="utopia-homes.public-answer.generate.v1",
        now=NOW,
    )
    assert authority.profile_release_id == "profiles-2026-09-17.1"
    assert authority.privacy_policy_release_id == "privacy-2026-09-17.1"
    assert authority.spending_grant_release_id == "grant-utopia-public-2026-09-18.1"


def test_missing_current_grant_fails_closed_before_service_construction() -> None:
    with pytest.raises(SignedReleaseRejected, match="complete_release_set_unavailable"):
        authorize_release_set(
            [verified_release("execution-profile"), verified_release("privacy-policy")],
            profile_id="utopia-homes.public-answer.generate.v1",
            now=NOW,
        )


class BundleAuthorityReader:
    def __init__(self) -> None:
        inventory_item = vector(BUNDLE / "vectors" / "positive" / "inventory.pos.bootstrap.json")
        self.inventory_jws = str(inventory_item["compact_jws"]).encode()
        self.releases = {
            ("execution_profile", "utopia-homes.public-answer.generate.v1"): self._release(
                "execution-profile"
            ),
            ("privacy_policy", "privacy-2026-09-17.1"): self._release("privacy-policy"),
            ("spending_grant", "utopia-public"): self._release("spending-grant"),
        }

    @staticmethod
    def _release(name: str) -> bytes:
        item = vector(BUNDLE / "vectors" / "positive" / f"release.pos.{name}.json")
        return str(item["compact_jws"]).encode()

    def load_active_inventory_jws(self, environment: str) -> bytes:
        assert environment == "staging"
        return self.inventory_jws

    def load_active_jws(self, scope: object, release_type: str, subject_id: str) -> bytes:
        del scope
        try:
            return self.releases[(release_type, subject_id)]
        except KeyError as exc:
            raise SignedReleaseRejected("active_release_unavailable") from exc

    def load_active_jws_by_release_id(
        self, scope: object, release_type: str, release_id: str
    ) -> bytes:
        del scope
        try:
            return self.releases[(release_type, release_id)]
        except KeyError as exc:
            raise SignedReleaseRejected("active_release_unavailable") from exc


def test_cold_start_resolves_and_reverifies_complete_authority_chain() -> None:
    authority = load_authorized_profile(
        BundleAuthorityReader(),
        scope=object(),
        root_key_id="tiamat-trust-root-staging-1",
        root_public_key=root_key(),
        issuer="stoin-control",
        environment="staging",
        caller_id="stoin:synth:utopia-homes",
        realm="utopia-homes",
        profile_id="utopia-homes.public-answer.generate.v1",
        partition_id="utopia-public",
        now=NOW,
    )
    assert authority.profile_release_id == "profiles-2026-09-17.1"
    assert authority.privacy_policy_release_id == "privacy-2026-09-17.1"
    assert authority.spending_grant_release_id == "grant-utopia-public-2026-09-18.1"


def test_cold_start_fails_closed_when_linked_policy_is_unavailable() -> None:
    reader = BundleAuthorityReader()
    del reader.releases[("privacy_policy", "privacy-2026-09-17.1")]
    with pytest.raises(SignedReleaseRejected, match="active_release_unavailable"):
        load_authorized_profile(
            reader,
            scope=object(),
            root_key_id="tiamat-trust-root-staging-1",
            root_public_key=root_key(),
            issuer="stoin-control",
            environment="staging",
            caller_id="stoin:synth:utopia-homes",
            realm="utopia-homes",
            profile_id="utopia-homes.public-answer.generate.v1",
            partition_id="utopia-public",
            now=NOW,
        )
