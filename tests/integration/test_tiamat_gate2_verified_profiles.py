"""Gate 2: serving takes its profile only from verified signed releases.

Each case mints a release root for its own disposable environment, signs a trust inventory, a
profile, its privacy policy and the partition's grant, and installs them through the authority
store's ordinary verify, stage and activate path as the release manager. Serving then resolves the
profile by re-verifying those exact bytes against the pinned root.
"""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.postgres_authority import PostgresSignedAuthorityStore
from lucy.shared_execution.verified_profiles import VerifiedProfileAuthority
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate1_eligibility import _bare_environment
from tests.integration.test_tiamat_gate1_served_api import (
    RELEASE,
    _error,
    _original,
    _record_rows,
    _serve,
)
from tests.integration.test_tiamat_gate1a_execution import _Environment
from tests.integration.tiamat_signed_trust import (
    AUTHORITY_ISSUER,
    ROOT_KEY_ID,
    SignedProfile,
    SyntheticReleaseTrust,
    install_signed_authority,
)
from tests.unit.test_shared_execution_api_rc1 import PROFILE, body

SIGNED = SignedProfile(
    profile_id=PROFILE,
    release_id=RELEASE.release_id,
    policy_id=RELEASE.privacy_policy_id,
    policy_release_id=RELEASE.privacy_policy_release_id,
    provider_route_id=RELEASE.provider_route_id,
    rate_release_id=RELEASE.rate_release_id,
    maximum_output_tokens=RELEASE.maximum_output_tokens,
    maximum_reservable_microusd=RELEASE.maximum_cost_microusd,
    timeout_ceiling_ms=12_000,
)


def _signed_environment(
    disposable_roles: DisposableRoles, profile: SignedProfile = SIGNED
) -> tuple[_Environment, SyntheticReleaseTrust]:
    env = _bare_environment(disposable_roles)
    trust = SyntheticReleaseTrust(env.environment, env.scope.caller_id, env.scope.realm)
    install_signed_authority(trust, env.release_manager, env.recovery, profile)
    return env, trust


def _verified(env: _Environment, trust: SyntheticReleaseTrust) -> VerifiedProfileAuthority:
    return VerifiedProfileAuthority(
        store=PostgresSignedAuthorityStore(env.runtime),
        scope=env.scope,
        authority_issuer=AUTHORITY_ISSUER,
        root_key_id=ROOT_KEY_ID,
        root_public_key=trust.root_public_key,
    )


def test_the_served_profile_is_the_verified_signed_content(
    disposable_roles: DisposableRoles,
) -> None:
    env, trust = _signed_environment(disposable_roles)

    profile = _verified(env, trust).current(PROFILE)

    assert profile is not None
    assert (profile.release_id, profile.provider_route_id, profile.rate_release_id) == (
        SIGNED.release_id,
        SIGNED.provider_route_id,
        SIGNED.rate_release_id,
    )
    assert (profile.privacy_policy_id, profile.privacy_policy_release_id) == (
        SIGNED.policy_id,
        SIGNED.policy_release_id,
    )
    assert profile.deadline_ms == SIGNED.timeout_ceiling_ms
    assert profile.maximum_cost_microusd == SIGNED.maximum_reservable_microusd
    assert profile.allowed_modes == frozenset({"text"})


def test_a_request_is_served_under_verified_authority(
    disposable_roles: DisposableRoles,
) -> None:
    env, trust = _signed_environment(disposable_roles)
    served = _serve(env, private_key=Ed25519PrivateKey.generate(), profiles=_verified(env, trust))
    document = _original(served, body(), uuid4())
    assert document["profile_release_id"] == SIGNED.release_id
    assert served.transport.calls == 1


def test_altered_signed_bytes_are_not_authority(disposable_roles: DisposableRoles) -> None:
    """A stored profile whose signature no longer verifies yields no profile and admits nothing."""

    env, trust = _signed_environment(disposable_roles)
    with psycopg.connect(env.release_manager, autocommit=True) as manager:
        manager.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        manager.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        manager.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        altered = manager.execute(
            """
            UPDATE tiamat.signed_releases
            SET exact_jws = overlay(exact_jws placing '\\x41'::bytea
                                    from octet_length(exact_jws) - 3 for 1)
            WHERE environment = %s AND release_type = 'execution_profile' AND subject_id = %s
            RETURNING 1
            """,
            (env.environment, PROFILE),
        ).fetchone()
    assert altered is not None

    authority = _verified(env, trust)
    assert authority.current(PROFILE) is None
    served = _serve(env, private_key=Ed25519PrivateKey.generate(), profiles=authority)
    _error(served.post(body(), uuid4()), 503, "privacy_route_unavailable")
    assert served.transport.calls == 0
    assert _record_rows(env) == []


def test_releases_under_a_different_root_are_not_authority(
    disposable_roles: DisposableRoles,
) -> None:
    env, trust = _signed_environment(disposable_roles)
    impostor = replace(trust, root=Ed25519PrivateKey.generate())
    assert _verified(env, impostor).current(PROFILE) is None


def test_a_policy_that_does_not_approve_the_route_is_not_authority(
    disposable_roles: DisposableRoles,
) -> None:
    env, trust = _signed_environment(
        disposable_roles, replace(SIGNED, approved_route_ids=("some-other-route",))
    )
    assert _verified(env, trust).current(PROFILE) is None


def test_a_verified_profile_the_contract_cannot_serve_is_not_current(
    disposable_roles: DisposableRoles,
) -> None:
    """A sub-second deadline ceiling cannot satisfy RC1's attempt budget, so it does not serve."""

    env, trust = _signed_environment(disposable_roles, replace(SIGNED, timeout_ceiling_ms=500))
    assert _verified(env, trust).current(PROFILE) is None


def _block(env: _Environment, reason: str) -> None:
    with psycopg.connect(env.recovery, autocommit=True) as recovery:
        for setting, value in (
            ("tiamat.environment", env.environment),
            ("tiamat.caller_id", env.scope.caller_id),
            ("tiamat.realm", env.scope.realm),
            ("tiamat.partition_id", env.scope.partition_id),
        ):
            recovery.execute("SELECT set_config(%s, %s, false)", (setting, value))
        recovery.execute(
            """
            UPDATE tiamat.spending_partitions SET blocked = true, block_reason = %s
            WHERE environment = %s AND caller_id = %s AND partition_id = %s
            """,
            (reason, env.environment, env.scope.caller_id, env.scope.partition_id),
        )


def _partition_block(env: _Environment) -> tuple[bool, str | None]:
    with psycopg.connect(env.recovery) as recovery:
        for setting, value in (
            ("tiamat.environment", env.environment),
            ("tiamat.caller_id", env.scope.caller_id),
            ("tiamat.realm", env.scope.realm),
            ("tiamat.partition_id", env.scope.partition_id),
        ):
            recovery.execute("SELECT set_config(%s, %s, false)", (setting, value))
        row = recovery.execute(
            """
            SELECT blocked, block_reason FROM tiamat.spending_partitions
            WHERE environment = %s AND caller_id = %s AND partition_id = %s
            """,
            (env.environment, env.scope.caller_id, env.scope.partition_id),
        ).fetchone()
    assert row is not None
    return bool(row[0]), row[1]


def test_activating_a_grant_does_not_clear_an_unfunded_settlement_block(
    disposable_roles: DisposableRoles,
) -> None:
    """Only the absence of a grant is answered by a grant; an unfunded liability is not."""

    env = _bare_environment(disposable_roles)
    _block(env, "settlement_liability_unfunded")
    trust = SyntheticReleaseTrust(env.environment, env.scope.caller_id, env.scope.realm)
    install_signed_authority(trust, env.release_manager, env.recovery, SIGNED)
    assert _partition_block(env) == (True, "settlement_liability_unfunded")


def test_activating_a_grant_clears_the_no_grant_block(disposable_roles: DisposableRoles) -> None:
    env = _bare_environment(disposable_roles)
    _block(env, "no_active_grant")
    trust = SyntheticReleaseTrust(env.environment, env.scope.caller_id, env.scope.realm)
    install_signed_authority(trust, env.release_manager, env.recovery, SIGNED)
    assert _partition_block(env) == (False, None)
