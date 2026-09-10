"""Bounded private-network client for one isolated recovery-journal writer."""

from __future__ import annotations

import http.client
import json
import os
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError

from lucy.cost_admission import ProviderAttemptAdmissionV1, ProviderAttemptRequestV1
from lucy.recovery_journal import RecoveryJournalError, RecoveryStreamKind


class WriterAcknowledgementResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    stream_kind: RecoveryStreamKind
    sequence: int
    event_digest: str


class HttpRecoveryJournalWriterClient:
    """Send only an exact event identifier to one stream-pinned writer."""

    def __init__(
        self,
        stream_kind: RecoveryStreamKind,
        hostport: str,
        token: str,
        *,
        timeout_seconds: int = 15,
    ) -> None:
        match = re.fullmatch(
            r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})", hostport
        )
        if match is None or not token or timeout_seconds not in range(1, 31):
            raise ValueError("private recovery writer configuration is invalid")
        port = int(match.group(2))
        if port > 65_535:
            raise ValueError("private recovery writer port is invalid")
        self._stream_kind = stream_kind
        self._host = match.group(1)
        self._port = port
        self._token = token
        self._timeout = timeout_seconds

    @classmethod
    def from_environment(
        cls, expected_kind: RecoveryStreamKind
    ) -> HttpRecoveryJournalWriterClient:
        try:
            configured_kind = RecoveryStreamKind(
                os.environ["LUCY_RECOVERY_WRITER_STREAM"]
            )
            if configured_kind is not expected_kind:
                raise RecoveryJournalError("private recovery writer stream differs")
            return cls(
                configured_kind,
                os.environ["LUCY_RECOVERY_WRITER_HOSTPORT"],
                os.environ["LUCY_RECOVERY_WRITER_TOKEN"],
            )
        except (KeyError, ValueError):
            raise RecoveryJournalError("private recovery writer is unavailable") from None

    def append_pending(self, event_id: UUID) -> WriterAcknowledgementResultV1:
        connection = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout
        )
        try:
            connection.request(
                "POST",
                f"/v1/recovery/events/{event_id}",
                body=b"",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Length": "0",
                },
            )
            response = connection.getresponse()
            raw = response.read(4097)
        except (OSError, http.client.HTTPException) as exc:
            raise RecoveryJournalError("private recovery writer is unavailable") from exc
        finally:
            connection.close()
        if response.status != 200 or len(raw) > 4096:
            raise RecoveryJournalError("private recovery writer rejected the event")
        try:
            result = WriterAcknowledgementResultV1.model_validate(json.loads(raw))
        except (json.JSONDecodeError, UnicodeError, ValidationError):
            raise RecoveryJournalError("private recovery writer response is invalid") from None
        if (
            result.event_id != event_id
            or result.stream_kind is not self._stream_kind
            or result.sequence < 1
            or re.fullmatch(r"[0-9a-f]{64}", result.event_digest) is None
        ):
            raise RecoveryJournalError("private recovery writer response differs")
        return result

    def append_reservation(self, admission: ProviderAttemptAdmissionV1) -> str:
        if admission.state != "PERSISTENCE_PENDING":
            raise RecoveryJournalError("cost reservation is not pending persistence")
        return self.append_pending(admission.event_id).event_digest

    def append_outcome(
        self,
        *,
        attempt: ProviderAttemptRequestV1,
        admission: ProviderAttemptAdmissionV1,
        incurred_microusd: int,
        provider_reference_commitment: str,
    ) -> str:
        if (
            admission.state not in {"SETTLEMENT_PENDING", "OVER_CAP_PENDING"}
            or admission.attempt_id != attempt.attempt_id
            or incurred_microusd < 0
            or re.fullmatch(r"[0-9a-f]{64}", provider_reference_commitment) is None
        ):
            raise RecoveryJournalError("cost outcome binding differs")
        return self.append_pending(admission.event_id).event_digest
