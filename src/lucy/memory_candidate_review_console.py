"""Loopback-only two-step owner review for private-memory candidates."""

from __future__ import annotations

import argparse
import hmac
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from lucy.chatgpt_import import verified_intake_path
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_candidate_review import (
    AuthorizedCandidateReviewV1,
    CandidateReviewBundleArtifactV1,
    CandidateReviewChoiceV1,
    CandidateReviewProposalV1,
    authorize_candidate_review,
    propose_candidate_review,
)

_CONFIRMATION = "AUTHORIZE EXACT PRIVATE MEMORY REVIEW"


class CandidateReviewConsoleSettingsV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)
    intake_root: Path
    bundle_path: Path
    proposal_path: Path
    authorization_path: Path
    session_token: str = Field(min_length=32, max_length=512)
    owner_actor_id: str = Field(min_length=1, max_length=512)
    allowed_origins: tuple[str, ...] = ("http://127.0.0.1:8766",)


class CandidateReviewProposalInputV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    choices: tuple[CandidateReviewChoiceV1, ...] = Field(min_length=1, max_length=200)


class CandidateReviewProposalResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal: CandidateReviewProposalV1
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class CandidateReviewAuthorizationInputV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_approval_ref: UUID
    confirmation: str = Field(max_length=100)


class CandidateReviewAuthorizationResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    authorized_review: AuthorizedCandidateReviewV1
    replayed: bool


def create_candidate_review_console(
    settings: CandidateReviewConsoleSettingsV1,
) -> FastAPI:
    root = settings.intake_root.resolve(strict=True)
    bundle_path = verified_intake_path(settings.bundle_path, intake_root=root)
    proposal_path = _output_path(settings.proposal_path, root=root)
    authorization_path = _output_path(settings.authorization_path, root=root)
    if bundle_path.stat().st_size > 10_000_000:
        raise ValueError("candidate review bundle exceeds its local parsing limit")
    bundle_artifact = CandidateReviewBundleArtifactV1.model_validate_json(
        bundle_path.read_bytes()
    )
    app = FastAPI(title="Private Lucy candidate review", docs_url=None, redoc_url=None)
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

    def require_local_mutation(request: Request, origin: str | None) -> None:
        if origin is None or origin not in settings.allowed_origins:
            raise HTTPException(status_code=403, detail="local request origin rejected")
        if request.url.hostname not in {"127.0.0.1", "localhost"}:
            raise HTTPException(status_code=403, detail="local request host rejected")

    @app.get("/review", response_class=HTMLResponse)
    def review_page() -> str:
        return _review_html()

    @app.get("/review/app.js", response_class=PlainTextResponse)
    def review_script() -> Response:
        return PlainTextResponse(_review_script(), media_type="application/javascript")

    @app.get("/api/candidates")
    def candidates_api(
        authorization: Annotated[str | None, Header()] = None,
    ) -> CandidateReviewBundleArtifactV1:
        require_token(authorization)
        return bundle_artifact

    @app.post("/api/review-proposal")
    def propose_review(
        request: Request,
        proposed: CandidateReviewProposalInputV1,
        authorization: Annotated[str | None, Header()] = None,
        origin: Annotated[str | None, Header()] = None,
    ) -> CandidateReviewProposalResultV1:
        require_token(authorization)
        require_local_mutation(request, origin)
        if proposed.bundle_digest != bundle_artifact.bundle_digest:
            raise HTTPException(status_code=409, detail="candidate bundle version changed")
        try:
            proposal = propose_candidate_review(bundle_artifact.bundle, proposed.choices)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        serialized = canonical_json_bytes(
            {"proposal": proposal, "proposal_digest": proposal.digest}
        ) + b"\n"
        replayed = _write_exact_once(
            proposal_path, serialized, conflict="review proposal already differs"
        )
        return CandidateReviewProposalResultV1(
            proposal=proposal,
            proposal_digest=proposal.digest,
            replayed=replayed,
        )

    @app.post("/api/review-authorization")
    def authorize_review(
        request: Request,
        proposed: CandidateReviewAuthorizationInputV1,
        authorization: Annotated[str | None, Header()] = None,
        origin: Annotated[str | None, Header()] = None,
    ) -> CandidateReviewAuthorizationResultV1:
        require_token(authorization)
        require_local_mutation(request, origin)
        if not hmac.compare_digest(proposed.confirmation, _CONFIRMATION):
            raise HTTPException(status_code=422, detail="exact confirmation phrase required")
        proposal = _load_proposal(proposal_path)
        if (
            proposed.proposal_digest != proposal.digest
            or proposal.bundle_digest != bundle_artifact.bundle_digest
        ):
            raise HTTPException(status_code=409, detail="review proposal version changed")
        if authorization_path.exists():
            existing = AuthorizedCandidateReviewV1.model_validate_json(
                authorization_path.read_bytes()
            )
            if (
                existing.proposal_digest != proposed.proposal_digest
                or existing.owner_approval_ref != proposed.owner_approval_ref
                or existing.owner_actor_id != settings.owner_actor_id
            ):
                raise HTTPException(status_code=409, detail="review authorization already differs")
            return CandidateReviewAuthorizationResultV1(
                authorized_review=existing, replayed=True
            )
        authorized = authorize_candidate_review(
            proposal,
            expected_proposal_digest=proposed.proposal_digest,
            owner_approval_ref=proposed.owner_approval_ref,
            owner_actor_id=settings.owner_actor_id,
            approved_at=datetime.now(UTC),
        )
        try:
            authorization_path.parent.mkdir(parents=True, exist_ok=True)
            with authorization_path.open("xb") as output:
                output.write(canonical_json_bytes(authorized) + b"\n")
        except FileExistsError as exc:
            raise HTTPException(
                status_code=409, detail="review authorization raced with another request"
            ) from exc
        return CandidateReviewAuthorizationResultV1(
            authorized_review=authorized, replayed=False
        )

    return app


def _output_path(path: Path, *, root: Path) -> Path:
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError("review output must remain inside the verified intake root")
    return resolved


def _write_exact_once(path: Path, payload: bytes, *, conflict: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(payload)
    except FileExistsError as exc:
        if path.read_bytes() != payload:
            raise HTTPException(status_code=409, detail=conflict) from exc
        return True
    return False


def _load_proposal(path: Path) -> CandidateReviewProposalV1:
    if not path.exists() or path.stat().st_size > 10_000_000:
        raise HTTPException(status_code=409, detail="exact review proposal is unavailable")
    try:
        document = json.loads(path.read_bytes())
        if not isinstance(document, dict):
            raise ValueError("proposal document must be an object")
        proposal = CandidateReviewProposalV1.model_validate(document.get("proposal"))
        if document.get("proposal_digest") != proposal.digest:
            raise ValueError("proposal digest mismatch")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=409, detail="exact review proposal is invalid") from exc
    return proposal


def _review_html() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private Lucy candidate review</title></head>
<body><main><h1>Private Lucy candidate review</h1>
<p>Review every exact candidate. Nothing is approved until the second confirmation step.</p>
<button id="load" type="button">Load protected candidates</button><div id="status"></div>
<form id="choices" hidden><div id="candidates"></div>
<button type="submit">Create exact review proposal</button></form>
<section id="final" hidden><h2>Final exact proposal</h2><pre id="proposal"></pre>
<label>Type AUTHORIZE EXACT PRIVATE MEMORY REVIEW
<input id="confirmation" autocomplete="off"></label>
<button id="authorize" type="button">Authorize this exact proposal</button></section>
<pre id="result"></pre></main><script src="/review/app.js"></script></body></html>"""


def _review_script() -> str:
    return """
let token = "";
let artifact = null;
let proposalDigest = "";
document.getElementById("load").addEventListener("click", async () => {
  token = token || window.prompt("Local session token") || "";
  const response = await fetch("/api/candidates", {headers: {Authorization: `Bearer ${token}`}});
  if (!response.ok) { document.getElementById("status").textContent = "Access denied."; return; }
  artifact = await response.json();
  const container = document.getElementById("candidates"); container.replaceChildren();
  for (const item of artifact.bundle.items) {
    const candidate = item.candidate;
    const row = document.createElement("section");
    const text = document.createElement("pre");
    text.textContent = `${candidate.subject} | ${candidate.predicate} | ${candidate.object}\n` +
      `kind=${candidate.memory_kind}; status=${candidate.assertion_status}; ` +
      `uncertainty=${candidate.epistemic_status}; protection=${candidate.protection_class}\n` +
      `sources=${item.source_excerpts.map((source) => source.source_record_id + ":" +
      source.byte_start + "-" + source.byte_end + " quote=" + source.exact_quote).join("\n")}`;
    const select = document.createElement("select"); select.dataset.id = candidate.candidate_id;
    select.dataset.version = String(candidate.candidate_version);
    select.dataset.digest = item.candidate_digest;
    for (const value of ["accept_protected", "accept_ordinary_private",
      "mark_uncertain_protected", "reject", "defer"]) {
      const option = document.createElement("option"); option.value = value;
      option.textContent = value;
      select.appendChild(option);
    }
    row.appendChild(text); row.appendChild(select); container.appendChild(row);
  }
  document.getElementById("status").textContent =
    `${artifact.bundle.items.length} exact candidates; bundle ${artifact.bundle_digest}`;
  document.getElementById("choices").hidden = false;
});
document.getElementById("choices").addEventListener("submit", async (event) => {
  event.preventDefault();
  const choices = [...document.querySelectorAll("select[data-id]")].map((item) => ({
    candidate_id: item.dataset.id, candidate_version: Number(item.dataset.version),
    candidate_digest: item.dataset.digest, disposition: item.value
  }));
  const response = await fetch("/api/review-proposal", {method: "POST", headers: {
    Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
    body: JSON.stringify({bundle_digest: artifact.bundle_digest, choices})});
  const body = await response.json();
  if (!response.ok) { document.getElementById("result").textContent = body.detail; return; }
  proposalDigest = body.proposal_digest;
  document.getElementById("proposal").textContent = JSON.stringify(body.proposal, null, 2);
  document.getElementById("final").hidden = false;
});
document.getElementById("authorize").addEventListener("click", async () => {
  const response = await fetch("/api/review-authorization", {method: "POST", headers: {
    Authorization: `Bearer ${token}`, "Content-Type": "application/json"}, body: JSON.stringify({
      proposal_digest: proposalDigest, owner_approval_ref: crypto.randomUUID(),
      confirmation: document.getElementById("confirmation").value})});
  const body = await response.json();
  document.getElementById("result").textContent = response.ok ?
    `Authorized exact proposal ${body.authorized_review.proposal_digest}. ` +
    "No promotion executed." : body.detail;
});
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--proposal-output", type=Path, required=True)
    parser.add_argument("--authorization-output", type=Path, required=True)
    parser.add_argument("--session-token-file", type=Path, required=True)
    parser.add_argument("--owner-actor-id", required=True)
    parser.add_argument("--port", type=int, default=8766)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 1024 <= args.port <= 65_535:
        raise ValueError("console port is invalid")
    settings = CandidateReviewConsoleSettingsV1(
        intake_root=args.intake_root,
        bundle_path=args.bundle,
        proposal_path=args.proposal_output,
        authorization_path=args.authorization_output,
        session_token=args.session_token_file.read_text(encoding="utf-8").strip(),
        owner_actor_id=args.owner_actor_id,
        allowed_origins=(f"http://127.0.0.1:{args.port}", f"http://localhost:{args.port}"),
    )
    uvicorn.run(create_candidate_review_console(settings), host="127.0.0.1", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
