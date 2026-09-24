"""Temporary authenticated HTTPS intake for Ray's approved Hindsight backfill."""

from __future__ import annotations

import json
import os
import secrets
from hashlib import sha256
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from lucy.contracts.canonical import canonical_json_bytes

_HINDSIGHT_URL = "http://raymond-hindsight-api:8888/v1/default/banks/ray-personal/memories"
_CONTEXT = "Dated source evidence from Ray's approved ChatGPT export"
_MAX_BODY = 1_000_000


class SourceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Literal["approved_chatgpt_export"]
    archive_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_record_id: str = Field(min_length=1, max_length=512)
    source_conversation_id: str = Field(min_length=1, max_length=512)
    source_revision: str = Field(pattern=r"^[1-9][0-9]*$")
    speaker_role: Literal["owner", "assistant", "system"]
    attribution: Literal["historical_utterance"]


class BackfillItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: str = Field(pattern=r"^lucy-chatgpt:[0-9a-f]{64}$")
    content: str = Field(min_length=1, max_length=70_000)
    context: str
    update_mode: Literal["replace"]
    metadata: SourceMetadata
    timestamp: str | None = None

    @model_validator(mode="after")
    def exact_source_document(self) -> BackfillItem:
        expected = "lucy-chatgpt:" + sha256(
            f"{self.metadata.source_record_id}:r{self.metadata.source_revision}".encode()
        ).hexdigest()
        if self.document_id != expected or self.context != _CONTEXT:
            raise ValueError("backfill document identity differs")
        return self


class BackfillBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    archive_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: tuple[BackfillItem, ...] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def same_archive_and_distinct_sources(self) -> BackfillBatch:
        ids = [item.metadata.source_record_id for item in self.items]
        if (len(ids) != len(set(ids)) or any(
            item.metadata.archive_commitment != self.archive_commitment
            for item in self.items
        )):
            raise ValueError("backfill source identity differs")
        return self


def create_app(
    *, bearer_token: str, hindsight_key: str, archive_commitment: str,
) -> FastAPI:
    if (len(bearer_token) < 32 or len(hindsight_key) < 32
            or len(archive_commitment) != 64):
        raise ValueError("backfill intake configuration invalid")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/v1/raymond/hindsight/backfill")
    async def retain(
        request: Request, authorization: str | None = Header(default=None),
    ) -> dict[str, int | bool]:
        if authorization is None or not secrets.compare_digest(
            authorization, f"Bearer {bearer_token}"
        ):
            raise HTTPException(status_code=401, detail="backfill capability required")
        body = await request.body()
        if len(body) > _MAX_BODY:
            raise HTTPException(status_code=413, detail="backfill batch too large")
        try:
            batch = BackfillBatch.model_validate_json(body)
            if (canonical_json_bytes(batch) != body
                    or batch.archive_commitment != archive_commitment):
                raise ValueError("backfill commitment differs")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid backfill batch") from exc
        try:
            result = await run_in_threadpool(_forward, batch, hindsight_key)
        except (HTTPError, URLError, TimeoutError, RuntimeError) as exc:
            raise HTTPException(status_code=503, detail="Hindsight retain unavailable") from exc
        if not isinstance(result, dict) or result.get("success") is not True:
            raise HTTPException(status_code=503, detail="Hindsight retain incomplete")
        return {"accepted": True, "processed_count": len(batch.items)}

    return app


def _forward(batch: BackfillBatch, hindsight_key: str) -> object:
    wire = json.dumps({
        "items": [item.model_dump(exclude_none=True) for item in batch.items],
        "async": False,
    }, separators=(",", ":")).encode()
    outgoing = UrlRequest(
        _HINDSIGHT_URL, data=wire, method="POST",
        headers={"Authorization": f"Bearer {hindsight_key}",
                 "Content-Type": "application/json"},
    )
    with urlopen(outgoing, timeout=540) as response:  # noqa: S310 - fixed private URL
        if response.status != 200:
            raise RuntimeError("Hindsight retain unavailable")
        return json.load(response)


def main() -> None:
    if os.environ.get("RENDER") != "true" or os.environ.get("LUCY_ENVIRONMENT") != "production":
        raise SystemExit("backfill intake deployment boundary unavailable")
    import uvicorn

    app = create_app(
        bearer_token=os.environ["LUCY_HINDSIGHT_BACKFILL_TOKEN"],
        hindsight_key=os.environ["HINDSIGHT_API_KEY"],
        archive_commitment=os.environ["LUCY_HINDSIGHT_ARCHIVE_COMMITMENT"],
    )
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")),
                access_log=False)


if __name__ == "__main__":
    main()
