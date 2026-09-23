"""Bring a serving process up without a person in the loop.

An ordinary restart should not need an operator: the launcher gate runs, a claimant is issued and
consumed, and serving resumes. What it must not do is lower the bar. The anchor is read first and
every refusal still refuses, so an unreadable, unverifiable or non-dispatching anchor ends the
startup rather than triggering a retry loop that eventually invents authority.

The order matters. A claimant already waiting is consumed as it stands; only its absence invokes
the launcher. That keeps an unattended restart cheap, and it keeps the launcher's own refusals
authoritative, because nothing here retries them.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    PostgresExecutionLedger,
)
from lucy.shared_execution.recovery_anchor import (
    ExternalRecoveryAnchor,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
)
from lucy.shared_execution.runtime_anchor_watch import RuntimeAnchorWatch
from lucy.shared_execution.startup_attestation import (
    StartupAttestationIssuer,
    StartupAttestationRejected,
)


class ServedStartupRefused(RuntimeError):
    """The process may not serve, so it must not start."""


@dataclass(frozen=True)
class ServedRuntime:
    """What a started process holds: its fence, its watch, and the head it started under."""

    coordinator_generation: int
    anchor_transition_sha256: str
    watch: RuntimeAnchorWatch
    launcher_invoked: bool


def start_serving(
    *,
    anchor: ExternalRecoveryAnchor,
    identity: RecoveryAnchorIdentity,
    issuer: StartupAttestationIssuer | None,
    ledger: PostgresExecutionLedger,
    clock: Callable[[], datetime],
) -> ServedRuntime:
    """Read authority, obtain a claimant if one is needed, and consume exactly one.

    Without an issuer the process is consume-only: the launcher runs separately, holding the
    recovery credential a serving process must never hold, and a process that finds no claimant
    waiting refuses to start rather than making one.
    """

    try:
        transition = anchor.read(identity.key)
    except RecoveryAnchorRejected as exc:
        # Unreadable and unverifiable are both fatal here. Startup is the one moment where there
        # is no verified interval to fall back on.
        raise ServedStartupRefused(str(exc)) from exc

    launcher_invoked = False
    try:
        generation = ledger.consume_startup_attestation(transition.exact_sha256)
    except DispatchBlocked as exc:
        if issuer is None:
            raise ServedStartupRefused("startup_claimant_required") from exc
        launcher_invoked = True
        try:
            issuer.issue(now=clock())
        except StartupAttestationRejected as exc:
            raise ServedStartupRefused(str(exc)) from exc
        try:
            generation = ledger.consume_startup_attestation(transition.exact_sha256)
        except DispatchBlocked as exc:
            # Another process took the claimant this one just caused to be issued. That is a lost
            # race, not a reason to issue again: retrying here is how two coordinators appear.
            raise ServedStartupRefused(str(exc)) from exc

    return ServedRuntime(
        coordinator_generation=generation,
        anchor_transition_sha256=transition.exact_sha256,
        watch=RuntimeAnchorWatch(
            anchor=anchor,
            identity=identity,
            consumed_transition_sha256=transition.exact_sha256,
            ledger=ledger,
            clock=clock,
        ),
        launcher_invoked=launcher_invoked,
    )
