"""The current profile, taken only from verified signed releases.

Serving resolves a profile the same way cold start does: the active trust inventory is verified
against the pinned release root, and the active profile, the privacy policy it names and the
partition's spending grant are each verified to their exact signed bytes and checked as one
complete set. Everything serving uses - the release, the route, the rates, the bounds, the
deadline ceiling and the policy - comes from that verified content. Nothing is configured locally.

This is re-read and re-verified on every call. The ledger independently requires the pinned
releases to be the active signed heads when it admits, and rechecks their revocation state at
dispatch and at the completed commit; this read decides compatibility and replay eligibility.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucy.shared_execution.durable_service import ServedProfile
from lucy.shared_execution.postgres_authority import (
    AuthorityScope,
    AuthorityStoreUnavailable,
    AuthorityTransitionRejected,
    PostgresSignedAuthorityStore,
)
from lucy.shared_execution.postgres_ledger import LedgerScope, LedgerUnavailable
from lucy.shared_execution.signed_releases import SignedReleaseRejected, load_authorized_profile

# RC1 section 6: the caller's attempt budget is 1,000 to 18,000 ms, so no profile deadline beyond
# that ceiling can be used, and one below its floor cannot serve any request.
_DEADLINE_CEILING_MS = 18_000


class VerifiedProfileAuthority:
    def __init__(
        self,
        *,
        store: PostgresSignedAuthorityStore,
        scope: LedgerScope,
        authority_issuer: str,
        root_key_id: str,
        root_public_key: Ed25519PublicKey,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._scope = scope
        self._authority = AuthorityScope(
            scope.environment, authority_issuer, scope.caller_id, scope.realm
        )
        self._root_key_id = root_key_id
        self._root_public_key = root_public_key
        self._clock = clock

    def current(self, profile_id: str) -> ServedProfile | None:
        try:
            authorized = load_authorized_profile(
                self._store,
                scope=self._authority,
                root_key_id=self._root_key_id,
                root_public_key=self._root_public_key,
                issuer=self._authority.issuer,
                environment=self._scope.environment,
                caller_id=self._scope.caller_id,
                realm=self._scope.realm,
                profile_id=profile_id,
                partition_id=self._scope.partition_id,
                now=self._clock(),
            )
        except (SignedReleaseRejected, AuthorityTransitionRejected):
            # Absent, inactive, unverifiable or incomplete authority is no current profile.
            return None
        except AuthorityStoreUnavailable as exc:
            raise LedgerUnavailable("signed authority is unavailable") from exc
        try:
            return ServedProfile(
                profile_id=authorized.profile_id,
                release_id=authorized.profile_release_id,
                allowed_modes=authorized.allowed_output_modes,
                maximum_output_tokens=authorized.maximum_output_tokens,
                maximum_cost_microusd=authorized.maximum_reservable_microusd,
                provider_route_id=authorized.provider_route_id,
                rate_release_id=authorized.rate_release_id,
                eligibility_generation=1,
                deadline_ms=min(authorized.timeout_ceiling_ms, _DEADLINE_CEILING_MS),
                privacy_policy_id=authorized.privacy_policy_id,
                privacy_policy_release_id=authorized.privacy_policy_release_id,
            )
        except ValueError:
            # A verified profile this contract cannot serve, such as a sub-second deadline.
            return None
