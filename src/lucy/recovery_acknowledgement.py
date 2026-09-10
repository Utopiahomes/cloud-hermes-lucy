"""DB-only reconciliation of exact independent-journal acknowledgements."""

from __future__ import annotations

import http.client
import json
import os
import re
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError

from lucy.authority_recovery import AuthorityTransitionResultV1, PendingAuthorityEventV1
from lucy.cost_admission import ProviderAttemptAdmissionV1
from lucy.cost_recovery import PendingCostEventV1
from lucy.recovery_journal import (
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryStreamKind,
)


class ExactAcknowledgementSource(Protocol):
    def exact_acknowledgement(
        self, event_id: UUID
    ) -> RecoveryAppendAcknowledgementV1 | None: ...


class RecoveryAcknowledgementResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    stream_kind: RecoveryStreamKind
    state: str


class HttpRecoveryAcknowledgementClient:
    """Bounded private-network client that transmits only an event identifier."""

    def __init__(self, hostport: str, token: str, *, timeout_seconds: int = 15) -> None:
        match = re.fullmatch(
            r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})", hostport
        )
        if match is None or not token or timeout_seconds not in range(1, 31):
            raise ValueError("private recovery client configuration is invalid")
        port = int(match.group(2))
        if port > 65_535:
            raise ValueError("private recovery client port is invalid")
        self._host = match.group(1)
        self._port = port
        self._token = token
        self._timeout = timeout_seconds

    @classmethod
    def from_environment(cls) -> HttpRecoveryAcknowledgementClient:
        try:
            return cls(
                os.environ["LUCY_RECOVERY_ACK_HOSTPORT"],
                os.environ["LUCY_RECOVERY_ACK_TOKEN"],
            )
        except KeyError:
            raise RecoveryJournalError("private recovery client is unavailable") from None

    def acknowledge(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> RecoveryAcknowledgementResultV1:
        del attempt_id
        result = self._post(RecoveryStreamKind.COST, event_id, head_digest)
        if result.state != "ADMITTED":
            raise RecoveryJournalError("cost reservation acknowledgement is incomplete")
        return result

    def acknowledge_outcome(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> RecoveryAcknowledgementResultV1:
        del attempt_id
        result = self._post(RecoveryStreamKind.COST, event_id, head_digest)
        if result.state not in {"SETTLED", "OVER_CAP"}:
            raise RecoveryJournalError("cost outcome acknowledgement is incomplete")
        return result

    def acknowledge_authority(
        self, event_id: UUID, *, head_digest: str
    ) -> RecoveryAcknowledgementResultV1:
        result = self._post(RecoveryStreamKind.AUTHORITY, event_id, head_digest)
        if result.state != "DURABLY_RECORDED":
            raise RecoveryJournalError("authority acknowledgement is incomplete")
        return result

    def _post(
        self, kind: RecoveryStreamKind, event_id: UUID, head_digest: str
    ) -> RecoveryAcknowledgementResultV1:
        if re.fullmatch(r"[0-9a-f]{64}", head_digest) is None:
            raise ValueError("recovery acknowledgement digest is invalid")
        connection = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout
        )
        try:
            connection.request(
                "POST",
                f"/v1/recovery/{kind.value}/acknowledgements/{event_id}",
                body=b"",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Length": "0",
                },
            )
            response = connection.getresponse()
            raw = response.read(4097)
        except (OSError, http.client.HTTPException) as exc:
            raise RecoveryJournalError("recovery acknowledgement is unavailable") from exc
        finally:
            connection.close()
        if response.status != 200 or len(raw) > 4096:
            raise RecoveryJournalError("recovery acknowledgement was rejected")
        try:
            result = RecoveryAcknowledgementResultV1.model_validate(json.loads(raw))
        except (json.JSONDecodeError, UnicodeError, ValidationError):
            raise RecoveryJournalError("recovery acknowledgement response is invalid") from None
        if result.event_id != event_id or result.stream_kind is not kind:
            raise RecoveryJournalError("recovery acknowledgement response differs")
        return result


class AuthorityAcknowledgementStore(Protocol):
    def pending(self, event_id: UUID) -> PendingAuthorityEventV1: ...

    def acknowledge(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_event_digest: str,
        journal_head_digest: str,
    ) -> AuthorityTransitionResultV1: ...


class CostAcknowledgementStore(Protocol):
    def pending(self, event_id: UUID) -> PendingCostEventV1: ...

    def acknowledge(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1: ...

    def acknowledge_outcome(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1: ...


class AuthorityAcknowledgementReceiver:
    """Acknowledge authority only after an exact durable journal read."""

    def __init__(
        self,
        store: AuthorityAcknowledgementStore,
        journal: ExactAcknowledgementSource,
    ) -> None:
        self._store = store
        self._journal = journal

    def receive(self, event_id: UUID) -> AuthorityTransitionResultV1:
        pending = self._store.pending(event_id)
        acknowledgement = self._journal.exact_acknowledgement(event_id)
        _require_exact(pending, acknowledgement, RecoveryStreamKind.AUTHORITY)
        assert acknowledgement is not None
        return self._store.acknowledge(
            event_id=event_id,
            journal_sequence=acknowledgement.resulting_head.sequence,
            journal_event_digest=acknowledgement.event_digest,
            journal_head_digest=acknowledgement.resulting_head.event_digest,
        )


class CostAcknowledgementReceiver:
    """Acknowledge cost only after an exact durable journal read."""

    def __init__(
        self,
        store: CostAcknowledgementStore,
        journal: ExactAcknowledgementSource,
    ) -> None:
        self._store = store
        self._journal = journal

    def receive(self, event_id: UUID) -> ProviderAttemptAdmissionV1:
        pending = self._store.pending(event_id)
        acknowledgement = self._journal.exact_acknowledgement(event_id)
        _require_exact(pending, acknowledgement, RecoveryStreamKind.COST)
        assert acknowledgement is not None
        head_digest = acknowledgement.resulting_head.event_digest
        if pending.event_type == "reservation":
            return self._store.acknowledge(
                attempt_id=pending.attempt_id,
                event_id=event_id,
                head_digest=head_digest,
            )
        return self._store.acknowledge_outcome(
            attempt_id=pending.attempt_id,
            event_id=event_id,
            head_digest=head_digest,
        )


def _require_exact(
    pending: PendingAuthorityEventV1 | PendingCostEventV1,
    acknowledgement: RecoveryAppendAcknowledgementV1 | None,
    expected_kind: RecoveryStreamKind,
) -> None:
    if (
        acknowledgement is None
        or pending.journal_sequence is None
        or pending.journal_event_digest is None
        or acknowledgement.event_id != pending.event_id
        or acknowledgement.event_digest != pending.journal_event_digest
        or acknowledgement.resulting_head.stream_kind is not expected_kind
        or acknowledgement.resulting_head.sequence != pending.journal_sequence
        or acknowledgement.resulting_head.event_digest != pending.journal_event_digest
        or (
            isinstance(pending, PendingAuthorityEventV1)
            and (
                acknowledgement.resulting_head.stream_id != pending.stream_id
                or acknowledgement.resulting_head.authority_epoch != pending.authority_epoch
            )
        )
    ):
        raise RecoveryJournalError("durable journal acknowledgement is unavailable")
