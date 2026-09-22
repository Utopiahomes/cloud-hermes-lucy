"""The lock that orders a security/privacy revocation against the executions it may suppress.

RC1 requires a revocation activated before an execution's completed commit to suppress that
candidate, and one activated after it to affect replay only. The two sides therefore need one
order. They get it from a transaction-scoped advisory lock per authority subject: a revocation
takes it exclusively before it writes, and dispatch and completion take it shared before they read
the subject's state. Whichever transaction holds it first commits first; the other then reads, or
writes over, that committed result.

An advisory lock is used rather than ``FOR SHARE`` because a row lock needs UPDATE privilege, and
the serving role must never hold UPDATE on the signed-release tables.

The two-integer key space is separate from the single-bigint idempotency-digest locks, so the two
families never contend. A hash collision between subjects only adds serialization, never a gap.
"""

from __future__ import annotations

import hashlib

# "TIAM" as a positive 32-bit integer: the class half of every authority-subject key.
AUTHORITY_LOCK_CLASS = 0x5449414D


def authority_subject_lock(
    environment: str, caller_id: str, realm: str, release_type: str, subject_id: str
) -> tuple[int, int]:
    """The advisory lock key for one authority subject within one caller scope."""

    digest = hashlib.sha256(
        "\x1f".join((environment, caller_id, realm, release_type, subject_id)).encode("utf-8")
    ).digest()
    return AUTHORITY_LOCK_CLASS, int.from_bytes(digest[:4], "big", signed=True)
