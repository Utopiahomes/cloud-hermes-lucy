"""Bounded same-network client for Raymond's policy-side interpreted recall."""

from __future__ import annotations

import http.client
import json
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.interpreted_recall import InterpretedAnswerContextV1


class InterpretedRecallUnavailable(RuntimeError):
    """The private policy boundary did not return a valid bounded context."""


class InterpretedPolicyLookupV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    query: str = Field(min_length=1, max_length=200)
    owner_interaction_ref: UUID
    limit: int = Field(default=5, ge=1, le=5)


class InterpretedPolicyResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contexts: tuple[InterpretedAnswerContextV1, ...] = Field(max_length=5)
    read_only: bool


class HttpInterpretedRecallClient:
    def __init__(self, hostport: str, token: str) -> None:
        match = re.fullmatch(r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})", hostport)
        if match is None or not token or int(match.group(2)) > 65_535:
            raise ValueError("private interpretation policy client configuration is invalid")
        self._host = match.group(1)
        self._port = int(match.group(2))
        self._token = token

    def lookup(self, request: InterpretedPolicyLookupV1) -> InterpretedPolicyResultV1:
        body = request.model_dump_json().encode("utf-8")
        connection = http.client.HTTPConnection(self._host, self._port, timeout=10)
        try:
            connection.request(
                "POST", "/internal/v1/memory/interpreted-context",
                body=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = connection.getresponse()
            raw = response.read(131_073)
        except (OSError, http.client.HTTPException) as exc:
            raise InterpretedRecallUnavailable("private interpretation policy unavailable") from exc
        finally:
            connection.close()
        if response.status != 200 or len(raw) > 131_072:
            raise InterpretedRecallUnavailable("private interpretation policy rejected lookup")
        try:
            result = InterpretedPolicyResultV1.model_validate(json.loads(raw))
        except (ValueError, UnicodeError) as exc:
            raise InterpretedRecallUnavailable(
                "private interpretation response is invalid"
            ) from exc
        if result.read_only is not True:
            raise InterpretedRecallUnavailable("private interpretation response is not read-only")
        return result
