"""Content-free private-network smoke test for Raymond's Hindsight service."""

from __future__ import annotations

import json
import os
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BANK = "ray-personal"
DOC_A = "lucy-synthetic-hindsight-probe-a"
DOC_B = "lucy-synthetic-hindsight-probe-b"


def _request(method: str, path: str, body: object | None = None,
             *, authorized: bool = True) -> tuple[int, object]:
    base = os.environ["HINDSIGHT_PRIVATE_URL"].rstrip("/")
    if base != "http://raymond-hindsight-api:8888":
        raise RuntimeError("Hindsight private destination differs")
    headers = {"Content-Type": "application/json"}
    if authorized:
        headers["Authorization"] = f"Bearer {os.environ['HINDSIGHT_API_KEY']}"
    wire = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = Request(base + path, data=wire, headers=headers, method=method)
    try:
        with urlopen(req, timeout=180) as response:  # noqa: S310 - exact private URL
            raw = response.read(500_001)
            if len(raw) > 500_000:
                raise RuntimeError("Hindsight response too large")
            return response.status, json.loads(raw) if raw else None
    except HTTPError as exc:
        return exc.code, None


def _memory_path(suffix: str = "") -> str:
    return f"/v1/default/banks/{BANK}/memories{suffix}"


def _recall(query: str) -> object:
    status, result = _request("POST", _memory_path("/recall"),
                              {"query": query, "budget": "low"})
    if status != 200:
        raise RuntimeError(f"Hindsight recall failed: HTTP {status}")
    return result


def _recall_text(result: object) -> str:
    if not isinstance(result, dict) or not isinstance(result.get("results"), list):
        raise RuntimeError("Hindsight recall response shape differs")
    return " ".join(
        entry.get("text", "") for entry in result["results"]
        if isinstance(entry, dict) and isinstance(entry.get("text"), str)
    ).lower()


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"health", "synthetic", "after_restart"}:
        raise SystemExit("usage: hindsight_private_probe.py health|synthetic|after_restart")
    phase = sys.argv[1]
    status, _ = _request("GET", "/health", authorized=False)
    if status != 200:
        raise RuntimeError(f"Hindsight health failed: HTTP {status}")
    denied, _ = _request("POST", _memory_path("/recall"),
                         {"query": "synthetic"}, authorized=False)
    if denied not in {401, 403}:
        raise RuntimeError(f"Hindsight private authentication failed: HTTP {denied}")
    if phase == "health":
        print("HINDSIGHT_PROBE:" + json.dumps({"phase": phase, "health": True,
                                               "unauthorized_denied": True}))
        return
    if phase == "synthetic":
        items = [
            {"content": "Synthetic probe: Iris filed a copper notebook in the west cabinet.",
             "document_id": DOC_A, "context": "synthetic memory lifecycle test",
             "metadata": {"source_record_id": "synthetic-a"}},
            {"content": "Synthetic probe: the west cabinet was moved to the blue room.",
             "document_id": DOC_B, "context": "synthetic memory lifecycle test",
             "metadata": {"source_record_id": "synthetic-b"}},
        ]
        for item in items:
            code, result = _request("POST", _memory_path(),
                                    {"items": [item], "async": False})
            if code != 200 or not isinstance(result, dict) or not result.get("success"):
                raise RuntimeError(f"synthetic retain failed: HTTP {code}")
        recalled = _recall_text(_recall("Where did Iris keep the synthetic copper notebook?"))
        if not all(part in recalled for part in ("iris", "copper", "notebook")):
            raise RuntimeError("synthetic fact was not recalled")
        reflected_code, reflected = _request(
            "POST", f"/v1/default/banks/{BANK}/reflect",
            {"query": "Where is Iris's synthetic copper notebook after the cabinet moved?"},
        )
        if reflected_code != 200 or not isinstance(reflected, dict):
            raise RuntimeError(f"synthetic reflection failed: HTTP {reflected_code}")
        reflection_text = str(reflected.get("text", "")).lower()
        if not all(part in reflection_text for part in ("iris", "notebook")):
            raise RuntimeError("synthetic reflection omitted the related memories")
        correction = {
            "content": "Synthetic correction: Iris filed the copper notebook in the east cabinet, "
                       "not the west cabinet.",
            "document_id": DOC_A, "update_mode": "replace",
            "context": "synthetic memory correction test",
            "metadata": {"source_record_id": "synthetic-a-corrected"},
        }
        code, result = _request("POST", _memory_path(),
                                {"items": [correction], "async": False})
        if code != 200 or not isinstance(result, dict) or not result.get("success"):
            raise RuntimeError(f"synthetic correction failed: HTTP {code}")
        corrected = _recall_text(_recall(
            "Which cabinet contains Iris's synthetic copper notebook?"
        ))
        if "east" not in corrected:
            raise RuntimeError("synthetic correction was not recalled")
        code, _ = _request("DELETE", f"/v1/default/banks/{BANK}/documents/{DOC_B}")
        if code not in {200, 204}:
            raise RuntimeError(f"synthetic deletion failed: HTTP {code}")
        deleted_code, _ = _request("GET", f"/v1/default/banks/{BANK}/documents/{DOC_B}")
        if deleted_code != 404:
            raise RuntimeError("deleted synthetic document remains readable")
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "health": True, "unauthorized_denied": True,
            "recalled": True, "reflected": True,
            "corrected_recalled": True, "deleted_document_absent": True,
        }, sort_keys=True))
        return
    recovered = _recall_text(_recall("Which cabinet contains Iris's synthetic copper notebook?"))
    if "east" not in recovered:
        raise RuntimeError("synthetic memory not recalled after restart")
    print("HINDSIGHT_PROBE:" + json.dumps({"phase": phase,
                                           "recalled_after_restart": True}))


if __name__ == "__main__":
    main()
