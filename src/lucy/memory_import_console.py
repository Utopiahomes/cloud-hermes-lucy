"""Loopback-only review surface for local private-memory import inventory."""

from __future__ import annotations

import argparse
import hmac
from collections.abc import Awaitable, Callable
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from lucy.chatgpt_import import ChatGPTExportInventoryV1, verified_intake_path
from lucy.contracts.canonical import canonical_json_bytes, canonical_sha256

_SELECTION_PREFIX = b"LUCY-PRIVATE-MEMORY-PILOT-SELECTION-V1\x00"


class ImportConsoleSettingsV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)
    intake_root: Path
    inventory_path: Path
    selection_path: Path
    session_token: str = Field(min_length=32, max_length=512)
    destination_content_scope_id: UUID
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:8765",)


class PilotSelectionInputV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    inventory_archive_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    conversation_ids: tuple[str, ...] = Field(min_length=1, max_length=20)
    max_model_spend_microusd: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=100)
    expires_at: datetime

    @model_validator(mode="after")
    def unique_conversations(self) -> PilotSelectionInputV1:
        if len(set(self.conversation_ids)) != len(self.conversation_ids):
            raise ValueError("pilot conversation IDs must be unique")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("pilot expiry must be timezone-aware")
        return self


class PilotConversationSelectionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    conversation_id: str
    title: str
    created_at: datetime | None
    updated_at: datetime | None
    message_count: int = Field(ge=0)
    displayed_message_count: int = Field(ge=0)
    alternate_message_count: int = Field(ge=0)
    missing_timestamp_count: int = Field(ge=0)
    missing_content_count: int = Field(ge=0)
    attachment_reference_count: int = Field(ge=0)
    supported_text_bytes: int = Field(ge=0)
    estimated_source_tokens: int = Field(ge=0)
    proposed_domain_tags: tuple[str, ...]


class PilotSelectionProposalV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["1"] = "1"
    inventory_archive_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    destination_content_scope_id: UUID
    selected_conversations: tuple[PilotConversationSelectionV1, ...] = Field(
        min_length=1, max_length=20
    )
    selected_record_count: int = Field(ge=1)
    selected_attachment_reference_count: int = Field(ge=0)
    selected_source_bytes: int = Field(ge=0)
    estimated_source_tokens: int = Field(ge=0)
    default_protection: Literal["protected"] = "protected"
    max_model_spend_microusd: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    expires_at: datetime
    authorization_state: Literal["proposed_not_authorized"] = "proposed_not_authorized"

    @model_validator(mode="after")
    def exact_aggregates(self) -> PilotSelectionProposalV1:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("pilot selection expiry must be timezone-aware")
        if len({item.conversation_id for item in self.selected_conversations}) != len(
            self.selected_conversations
        ):
            raise ValueError("selected conversation IDs must be unique")
        expected = (
            sum(item.message_count for item in self.selected_conversations),
            sum(
                item.attachment_reference_count
                for item in self.selected_conversations
            ),
            sum(item.supported_text_bytes for item in self.selected_conversations),
            sum(item.estimated_source_tokens for item in self.selected_conversations),
        )
        actual = (
            self.selected_record_count,
            self.selected_attachment_reference_count,
            self.selected_source_bytes,
            self.estimated_source_tokens,
        )
        if actual != expected:
            raise ValueError("pilot selection aggregates do not match exact conversations")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_SELECTION_PREFIX)


class PilotSelectionResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal: PilotSelectionProposalV1
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


def create_import_console(settings: ImportConsoleSettingsV1) -> FastAPI:
    root = settings.intake_root.resolve(strict=True)
    inventory_path = verified_intake_path(settings.inventory_path, intake_root=root)
    selection_path = settings.selection_path.resolve(strict=False)
    if not selection_path.is_relative_to(root):
        raise ValueError("selection output must remain inside the verified intake root")
    inventory = ChatGPTExportInventoryV1.model_validate_json(inventory_path.read_bytes())
    app = FastAPI(title="Private Lucy local import review", docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def private_response_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; connect-src 'self'; "
            "style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    def require_token(authorization: str | None) -> None:
        expected = f"Bearer {settings.session_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="local session token required")

    @app.get("/imports", response_class=HTMLResponse)
    def imports_page() -> str:
        return _console_html()

    @app.get("/imports/app.js", response_class=PlainTextResponse)
    def imports_script() -> Response:
        return PlainTextResponse(_console_script(), media_type="application/javascript")

    @app.get("/api/inventory")
    def inventory_api(
        authorization: Annotated[str | None, Header()] = None,
    ) -> ChatGPTExportInventoryV1:
        require_token(authorization)
        return inventory

    @app.post("/api/pilot-selection")
    def propose_pilot(
        request: Request,
        proposed: PilotSelectionInputV1,
        authorization: Annotated[str | None, Header()] = None,
        origin: Annotated[str | None, Header()] = None,
    ) -> PilotSelectionResultV1:
        require_token(authorization)
        if origin is None or origin not in settings.allowed_origins:
            raise HTTPException(status_code=403, detail="local request origin rejected")
        if request.url.hostname not in {"127.0.0.1", "localhost"}:
            raise HTTPException(status_code=403, detail="local request host rejected")
        if proposed.inventory_archive_commitment != inventory.archive_commitment:
            raise HTTPException(status_code=409, detail="inventory version changed")
        if proposed.expires_at <= datetime.now(proposed.expires_at.tzinfo):
            raise HTTPException(status_code=422, detail="pilot proposal expiry must be future")
        by_id = {item.conversation_id: item for item in inventory.conversations}
        if any(item not in by_id for item in proposed.conversation_ids):
            raise HTTPException(status_code=422, detail="selection contains unknown conversation")
        selected = tuple(by_id[item] for item in proposed.conversation_ids)
        proposal = PilotSelectionProposalV1(
            inventory_archive_commitment=inventory.archive_commitment,
            destination_content_scope_id=settings.destination_content_scope_id,
            selected_conversations=tuple(
                PilotConversationSelectionV1(
                    conversation_id=item.conversation_id,
                    title=item.title,
                    created_at=item.created_at,
                    updated_at=item.updated_at,
                    message_count=item.message_count,
                    displayed_message_count=item.displayed_message_count,
                    alternate_message_count=item.alternate_message_count,
                    missing_timestamp_count=item.missing_timestamp_count,
                    missing_content_count=item.missing_content_count,
                    attachment_reference_count=item.attachment_reference_count,
                    supported_text_bytes=item.supported_text_bytes,
                    estimated_source_tokens=item.estimated_source_tokens,
                    proposed_domain_tags=item.proposed_domain_tags,
                )
                for item in selected
            ),
            selected_record_count=sum(item.message_count for item in selected),
            selected_attachment_reference_count=sum(
                item.attachment_reference_count for item in selected
            ),
            selected_source_bytes=sum(item.supported_text_bytes for item in selected),
            estimated_source_tokens=sum(
                item.estimated_source_tokens for item in selected
            ),
            max_model_spend_microusd=proposed.max_model_spend_microusd,
            max_attempts=proposed.max_attempts,
            expires_at=proposed.expires_at,
        )
        serialized = canonical_json_bytes(
            {"proposal": proposal, "proposal_digest": proposal.digest}
        ) + b"\n"
        replayed = False
        selection_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with selection_path.open("xb") as output:
                output.write(serialized)
        except FileExistsError as exc:
            if selection_path.read_bytes() != serialized:
                raise HTTPException(
                    status_code=409, detail="pilot proposal already differs"
                ) from exc
            replayed = True
        return PilotSelectionResultV1(
            proposal=proposal,
            proposal_digest=proposal.digest,
            replayed=replayed,
        )

    return app


def _console_html() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private Lucy import review</title></head>
<body><main><h1>Private Lucy import review</h1>
<p>This local page proposes a pilot. It does not authorize or upload data.</p>
<p>Attachment contents are excluded from the initial pilot.</p>
<button id="load" type="button">Load local inventory</button><div id="status"></div>
<form id="proposal" hidden><fieldset><legend>Select 1–20 conversations</legend>
<div id="conversations"></div></fieldset>
<label>Hard model-spend ceiling (micro-USD)
<input id="spend" type="number" min="0" step="1" required></label>
<label>Maximum attempts
<input id="attempts" type="number" min="1" max="100" value="20" required></label>
<label>Expires at <input id="expiry" type="datetime-local" required></label>
<button type="submit">Save non-authorizing pilot proposal</button></form>
<pre id="result"></pre></main><script src="/imports/app.js"></script></body></html>"""


def _console_script() -> str:
    return """
let token = "";
let inventory = null;
document.getElementById("load").addEventListener("click", async () => {
  token = token || window.prompt("Local session token") || "";
  const response = await fetch("/api/inventory", {headers: {Authorization: `Bearer ${token}`}});
  const status = document.getElementById("status");
  const container = document.getElementById("conversations");
  container.replaceChildren();
  if (!response.ok) { status.textContent = "Inventory access denied."; return; }
  inventory = await response.json();
  status.textContent = `${inventory.conversations.length} conversations; no data uploaded.`;
  for (const conversation of inventory.conversations) {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = "conversation";
    checkbox.value = conversation.conversation_id;
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(
      `${conversation.title} — ${conversation.message_count} messages, ` +
      `${conversation.alternate_message_count} alternate, ` +
      `~${conversation.estimated_source_tokens} tokens, ` +
      `${conversation.attachment_reference_count} attachment references; ` +
      `tags: ${conversation.proposed_domain_tags.join(", ")}`));
    const row = document.createElement("div");
    row.appendChild(label);
    container.appendChild(row);
  }
  document.getElementById("proposal").hidden = false;
});
document.getElementById("proposal").addEventListener("submit", async (event) => {
  event.preventDefault();
  const selected = [...document.querySelectorAll('input[name="conversation"]:checked')]
    .map((item) => item.value);
  const result = document.getElementById("result");
  if (!inventory || selected.length < 1 || selected.length > 20) {
    result.textContent = "Select between 1 and 20 conversations."; return;
  }
  const expiry = new Date(document.getElementById("expiry").value);
  const payload = {
    inventory_archive_commitment: inventory.archive_commitment,
    conversation_ids: selected,
    max_model_spend_microusd: Number(document.getElementById("spend").value),
    max_attempts: Number(document.getElementById("attempts").value),
    expires_at: expiry.toISOString()
  };
  const response = await fetch("/api/pilot-selection", {
    method: "POST", headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  const responseBody = await response.json();
  if (!response.ok) { result.textContent = `Proposal rejected: ${responseBody.detail}`; return; }
  result.textContent = `Saved ${responseBody.proposal.selected_record_count} records; ` +
    `~${responseBody.proposal.estimated_source_tokens} source tokens; ` +
    `digest ${responseBody.proposal_digest}; status: proposed, NOT authorized.`;
});
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--selection-output", type=Path, required=True)
    parser.add_argument("--session-token-file", type=Path, required=True)
    parser.add_argument("--destination-content-scope-id", type=UUID, required=True)
    parser.add_argument("--port", type=int, default=8765)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 1024 <= args.port <= 65_535:
        raise ValueError("console port is invalid")
    settings = ImportConsoleSettingsV1(
        intake_root=args.intake_root,
        inventory_path=args.inventory,
        selection_path=args.selection_output,
        session_token=args.session_token_file.read_text(encoding="utf-8").strip(),
        destination_content_scope_id=args.destination_content_scope_id,
        allowed_origins=(f"http://127.0.0.1:{args.port}", f"http://localhost:{args.port}"),
    )
    uvicorn.run(create_import_console(settings), host="127.0.0.1", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
