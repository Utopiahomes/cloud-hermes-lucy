"""Keep a serving process's view of external recovery authority current.

A running executor cannot wait for its claimant to lapse before noticing that authority was
withdrawn: Draft 0.5 section 6 requires a published quarantine to be observed within seconds, and
section 5 requires expiry and known quarantine to be checked at admission and at the final
dispatch gate. This holds the local half of that: a latch which closes on what the process itself
observes, and which nothing here can reopen.

The three outcomes are deliberately different:

* an observed quarantine, or any anchor which no longer authorizes dispatch, closes the latch at
  once and blocks the ledger gate as well;
* an unavailable anchor changes nothing, preserving only the already verified bounded interval,
  which the claimant's own expiry continues to bound in the database;
* an anchor which cannot be verified at all closes the latch, because an unverifiable record is
  not authority.

Reopening is not this object's business. A closed latch is the end of this process's authority;
a new claimant obtained through the launcher is what starts the next one.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from lucy.shared_execution.recovery_anchor import (
    ExternalRecoveryAnchor,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
)

RefreshOutcome = Literal["authority_current", "anchor_unavailable", "authority_withdrawn"]


class DispatchLatchStore(Protocol):
    """The durable half of the latch: blocking the gate for every process, not just this one."""

    def block_dispatch(self, reason: str) -> None: ...


@dataclass(frozen=True)
class RuntimeAuthorityClosed(RuntimeError):
    """This process may no longer dispatch, whatever the ledger would otherwise allow."""

    reason: str

    def __str__(self) -> str:
        return self.reason


class RuntimeAnchorWatch:
    """Observe external authority for one serving process and latch its dispatch closed."""

    def __init__(
        self,
        *,
        anchor: ExternalRecoveryAnchor,
        identity: RecoveryAnchorIdentity,
        consumed_transition_sha256: str,
        ledger: DispatchLatchStore,
        clock: Callable[[], datetime],
    ) -> None:
        self._anchor = anchor
        self._identity = identity
        self._consumed = consumed_transition_sha256
        self._ledger = ledger
        self._clock = clock
        self._lock = threading.Lock()
        self._closed_reason: str | None = None

    @property
    def closed_reason(self) -> str | None:
        with self._lock:
            return self._closed_reason

    def require_open(self) -> None:
        """Refuse before admission and again at the final dispatch gate."""

        reason = self.closed_reason
        if reason is not None:
            raise RuntimeAuthorityClosed(reason)

    def close(self, reason: str) -> None:
        """Close the latch locally, then block the gate; a failed write never reopens it."""

        with self._lock:
            if self._closed_reason is None:
                self._closed_reason = reason
        try:
            self._ledger.block_dispatch(reason)
        except Exception:  # noqa: BLE001 - the local latch is authoritative for this process
            # Draft 0.5 section 6: failure to write the database does not reopen the local latch.
            return

    def refresh(self) -> RefreshOutcome:
        """Read the anchor once and act on what it says."""

        try:
            transition = self._anchor.read(self._identity.key)
        except RecoveryAnchorRejected as exc:
            if str(exc) == "recovery_anchor_unavailable":
                # Only the already verified interval survives; the claimant still bounds it.
                return "anchor_unavailable"
            self.close("recovery_anchor_unverifiable")
            return "authority_withdrawn"
        if transition.exact_sha256 != self._consumed:
            # The head moved under this process. Whether that is a quarantine, a renewal or a
            # rollback, this process's authority came from the record it consumed, not this one.
            self.close("recovery_anchor_superseded")
            return "authority_withdrawn"
        if transition.continuity != "continuity_established":
            self.close("recovery_continuity_withdrawn")
            return "authority_withdrawn"
        if transition.witness.status != "reconciled" or not transition.witness.valid_at(
            self._clock()
        ):
            self.close("recovery_witness_not_current")
            return "authority_withdrawn"
        return "authority_current"
