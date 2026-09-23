"""Control's one-off release runner (Gate 2 Proof 2, D4) on a disposable ledger.

The runner acts only as the release-manager login, over TLS, on the ledger the operator named. It
verifies the current inventory against the approved RELEASE-root pin and each release under it
immediately before a write, previews by default, activates policy and profile before the grant,
and reads every write back.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.postgres_authority import AuthorityScope
from lucy.shared_execution.recovery import create_spending_partition
from lucy.shared_execution.release_runner import (
    ReleaseRunnerRejected,
    RunnerContext,
    preview_or_activate,
    preview_or_stage,
)
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate2_reconciliation import (
    _Ledger,
    _report_checkpoint,
    make_ledger,
)
from tests.integration.tiamat_signed_trust import AUTHORITY_ISSUER, SyntheticReleaseTrust
from tests.integration.tiamat_signed_trust import ROOT_KEY_ID as RELEASE_ROOT_KEY_ID

REALM = "g2r-realm"
SUBJECTS = [
    ("execution_profile", "profile-runner"),
    ("privacy_policy", "policy-runner"),
    ("spending_grant", "partition-runner"),
]


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def ledger(disposable_roles: DisposableRoles) -> _Ledger:
    """Reconciled to generation 2 with the gate open, one first inventory, one partition."""

    ledger = make_ledger(disposable_roles)
    ledger.install_first_inventory(ledger.release.inventory_jws(SUBJECTS))
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    ledger.authorize(pending)
    create_spending_partition(
        disposable_roles.recovery,
        environment=ledger.environment,
        expected_ledger_id=ledger.identity.ledger_id,
        expected_storage_epoch=ledger.identity.storage_epoch,
        expected_recovery_generation=2,
        caller_id=ledger.release.caller_id,
        realm=REALM,
        partition_id="partition-runner",
    )
    return ledger


def _context(ledger: _Ledger, **changes: Any) -> RunnerContext:
    context = RunnerContext(
        database_url=ledger.roles.release_manager,
        expected_ledger_id=ledger.identity.ledger_id,
        scope=AuthorityScope(ledger.environment, AUTHORITY_ISSUER, ledger.release.caller_id, REALM),
        root_key_id=RELEASE_ROOT_KEY_ID,
        root_public_key=ledger.release.root_public_key,
    )
    return replace(context, **changes)


def _policy(ledger: _Ledger) -> bytes:
    return _policy_bytes(ledger.release, "policy-runner")


def _policy_bytes(release: SyntheticReleaseTrust, policy_id: str) -> bytes:
    return release.release_jws(
        "privacy_policy",
        policy_id,
        f"{policy_id}.1",
        {
            "policy_id": policy_id,
            "approved_provider_route_ids": ["route-runner"],
            "required_provider_privacy": ["zero_data_retention", "no_training"],
            "data_collection": "denied",
            "training": "denied",
            "fallback_allowed": False,
            "allowed_regions": ["us"],
            "retention_ceiling_seconds": 0,
            "eligibility_generation": 1,
        },
    )


def _profile(ledger: _Ledger, release_id: str = "profile-runner.1", **extra: Any) -> bytes:
    return _profile_bytes(ledger.release, "profile-runner", "policy-runner", release_id, **extra)


def _profile_bytes(
    release: SyntheticReleaseTrust,
    profile_id: str,
    policy_id: str,
    release_id: str | None = None,
    **extra: Any,
) -> bytes:
    return release.release_jws(
        "execution_profile",
        profile_id,
        release_id or f"{profile_id}.1",
        {
            "profile_id": profile_id,
            "provider_route_id": "route-runner",
            "model_id": "synthetic-model",
            "allowed_output_modes": ["text"],
            "maximum_input_tokens": 8_000,
            "maximum_output_tokens": 900,
            "maximum_context_tokens": 16_000,
            "timeout_ceiling_ms": 15_000,
            "privacy_policy_release_id": f"{policy_id}.1",
            "data_collection": "denied",
            "training": "denied",
            "zero_data_retention_required": True,
            "fallback_allowed": False,
            "rate_release_id": "rates-runner.1",
            "rates": {
                "input_per_million_microusd": 100_000,
                "output_per_million_microusd": 400_000,
                "reasoning_per_million_microusd": 400_000,
                "per_request_microusd": 0,
            },
            "maximum_reservable_microusd": 2_000,
        },
        **extra,
    )


def _grant(
    ledger: _Ledger | SyntheticReleaseTrust, release_id: str, partition: str = "partition-runner"
) -> bytes:
    # grant_releases is keyed by release ID across every environment: a reused ID is a conflict.
    now = datetime.now(UTC)
    release = ledger.release if isinstance(ledger, _Ledger) else ledger
    return release.release_jws(
        "spending_grant",
        partition,
        release_id,
        {
            "partition_id": partition,
            "budget_period_id": "period-runner",
            "period_start": _stamp(now - timedelta(hours=1)),
            "period_end": _stamp(now + timedelta(hours=6)),
            "allowance_microusd": 20_000,
            "maximum_concurrency": 2,
            "largest_per_call_microusd": 2_000,
            "contingency_reserve_microusd": 8_000,
        },
    )


def _stage_and_activate(context: RunnerContext, exact: bytes) -> dict[str, object]:
    now = datetime.now(UTC)
    preview = preview_or_stage(context, exact, now=now, confirm_jws_sha256=None)
    assert preview["status"] == "verified_not_written"
    digest = str(preview["jws_sha256"])
    assert preview_or_stage(context, exact, now=now, confirm_jws_sha256=digest)["status"] == (
        "staged_and_read_back"
    )
    assert preview_or_activate(context, exact, now=now, confirm_jws_sha256=None)["status"] == (
        "verified_not_activated"
    )
    return preview_or_activate(context, exact, now=now, confirm_jws_sha256=digest)


def _partition(ledger: _Ledger) -> tuple[Any, ...]:
    with psycopg.connect(ledger.roles.recovery) as recovery:
        row = recovery.execute(
            """
            SELECT blocked, allowance_microusd, active_grant_release_id
            FROM tiamat.spending_partitions
            WHERE environment = %s AND partition_id = 'partition-runner'
            """,
            (ledger.environment,),
        ).fetchone()
    assert row is not None
    return tuple(row)


def test_policy_profile_then_grant_activate_through_the_runner(ledger: _Ledger) -> None:
    context = _context(ledger)
    grant_id = f"grant-runner-{uuid4().hex[:8]}"
    for exact in (_policy(ledger), _profile(ledger), _grant(ledger, grant_id)):
        assert _stage_and_activate(context, exact)["status"] == "activated_and_read_back"
    assert _partition(ledger) == (False, 20_000, grant_id)


def test_a_preview_writes_nothing(ledger: _Ledger) -> None:
    context = _context(ledger)
    exact = _policy(ledger)
    preview_or_stage(context, exact, now=datetime.now(UTC), confirm_jws_sha256=None)
    with pytest.raises(ReleaseRunnerRejected, match="not_staged_as_supplied"):
        preview_or_activate(context, exact, now=datetime.now(UTC), confirm_jws_sha256=None)


def test_the_grant_waits_for_profile_and_policy(ledger: _Ledger) -> None:
    context = _context(ledger)
    grant = _grant(ledger, f"grant-runner-{uuid4().hex[:8]}")
    digest = str(
        preview_or_stage(context, grant, now=datetime.now(UTC), confirm_jws_sha256=None)[
            "jws_sha256"
        ]
    )
    preview_or_stage(context, grant, now=datetime.now(UTC), confirm_jws_sha256=digest)
    with pytest.raises(ReleaseRunnerRejected, match="grant_before_profile_and_policy"):
        preview_or_activate(context, grant, now=datetime.now(UTC), confirm_jws_sha256=digest)
    assert _partition(ledger) == (True, 0, None)


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("recovery_login", "login_is_not_the_release_manager"),
        ("other_ledger", "ledger_differs"),
        ("other_root", "release_runner_"),
        ("unlisted_subject", "release_runner_release_scope_invalid"),
        ("not_current", "release_runner_(key_not_usable|release_not_current)"),
        ("wrong_confirmation", "confirmation_differs"),
    ],
)
def test_the_runner_refuses_before_writing(ledger: _Ledger, case: str, reason: str) -> None:
    context = _context(ledger)
    exact = _policy(ledger)
    now = datetime.now(UTC)
    confirm: str | None = None
    if case == "recovery_login":
        context = _context(ledger, database_url=ledger.roles.recovery)
    elif case == "other_ledger":
        context = _context(ledger, expected_ledger_id=uuid4())
    elif case == "other_root":
        context = _context(ledger, root_public_key=Ed25519PrivateKey.generate().public_key())
    elif case == "unlisted_subject":
        exact = ledger.release.release_jws(
            "privacy_policy",
            "policy-unlisted",
            "policy-unlisted.1",
            {
                "policy_id": "policy-unlisted",
                "approved_provider_route_ids": ["route-runner"],
                "required_provider_privacy": ["zero_data_retention"],
                "data_collection": "denied",
                "training": "denied",
                "fallback_allowed": False,
                "allowed_regions": ["us"],
                "retention_ceiling_seconds": 0,
                "eligibility_generation": 1,
            },
        )
    elif case == "not_current":
        now = now + timedelta(days=30)
    else:
        confirm = "0" * 64
    with pytest.raises(ReleaseRunnerRejected, match=reason):
        preview_or_stage(context, exact, now=now, confirm_jws_sha256=confirm)
    with psycopg.connect(ledger.roles.recovery) as recovery:
        staged = recovery.execute(
            "SELECT count(*) FROM tiamat.signed_releases WHERE environment = %s",
            (ledger.environment,),
        ).fetchone()
    assert staged is not None and int(staged[0]) == 0


def test_activation_requires_succession(ledger: _Ledger) -> None:
    context = _context(ledger)
    _stage_and_activate(context, _policy(ledger))
    _stage_and_activate(context, _profile(ledger))
    # A second profile release that does not name the active one as its predecessor.
    rogue = _profile(ledger, "profile-runner.2", sequence=2, predecessor=None)
    digest = str(
        preview_or_stage(context, rogue, now=datetime.now(UTC), confirm_jws_sha256=None)[
            "jws_sha256"
        ]
    )
    preview_or_stage(context, rogue, now=datetime.now(UTC), confirm_jws_sha256=digest)
    with pytest.raises(ReleaseRunnerRejected, match="not_successor"):
        preview_or_activate(context, rogue, now=datetime.now(UTC), confirm_jws_sha256=digest)


def test_activation_refuses_a_blocked_gate(disposable_roles: DisposableRoles) -> None:
    """Staging is allowed while blocked; activation is not."""

    ledger = make_ledger(disposable_roles)
    ledger.install_first_inventory(ledger.release.inventory_jws(SUBJECTS))
    context = _context(ledger)
    exact = _policy(ledger)
    digest = str(
        preview_or_stage(context, exact, now=datetime.now(UTC), confirm_jws_sha256=None)[
            "jws_sha256"
        ]
    )
    preview_or_stage(context, exact, now=datetime.now(UTC), confirm_jws_sha256=digest)
    with pytest.raises(ReleaseRunnerRejected, match="recovery_gate_blocked"):
        preview_or_activate(context, exact, now=datetime.now(UTC), confirm_jws_sha256=digest)
