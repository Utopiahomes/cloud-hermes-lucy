"""Content-free private-network smoke test for Raymond's Hindsight service."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
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
    if len(sys.argv) != 2 or sys.argv[1] not in {
        "health", "synthetic", "reflect_only", "correct_delete", "after_restart",
        "clear_synthetic", "reviewed_three", "reviewed_full", "backfill_inventory",
        "nuance_diagnostic", "nuance_default", "nuance_metadata",
    }:
        raise SystemExit(
            "usage: hindsight_private_probe.py "
            "health|synthetic|reflect_only|correct_delete|after_restart|"
            "clear_synthetic|reviewed_three|reviewed_full|backfill_inventory|"
            "nuance_diagnostic|nuance_default|nuance_metadata"
        )
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
    if phase == "nuance_metadata":
        code, result = _request("POST", _memory_path("/recall"), {
            "query": "What did I actually confirm about Trial Gate and The Magician's Universal Aid tag, and what remains uncertain?",
            "budget": "low", "max_tokens": 3500,
            "types": ["observation", "world", "experience"],
        })
        if code != 200 or not isinstance(result, dict) or not isinstance(result.get("results"), list):
            raise RuntimeError("nuance metadata recall unavailable")
        rows = [row for row in result["results"] if isinstance(row, dict)]
        sources = Counter(str((row.get("metadata") or {}).get("source", "missing")) for row in rows)
        reviewed = [
            {"position": index,
             "trial_gate": "trial gate" in str(row.get("text", "")).lower(),
             "universal_aid": "universal aid" in str(row.get("text", "")).lower(),
             "guardian_locked": "guardian locked" in str(row.get("text", "")).lower(),
             "uncertainty": any(word in str(row.get("text", "")).lower() for word in
                                ("ambiguous", "unclear", "not confirmed", "unresolved")),
             "document_id_present": bool(row.get("document_id")),
             "source_ids_present": bool((row.get("metadata") or {}).get("source_record_ids")),
             "metadata_keys": sorted((row.get("metadata") or {}).keys())}
            for index, row in enumerate(rows)
            if (row.get("metadata") or {}).get("source") == "lucy_governed_reviewed_interpretation"
        ]
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "facts": len(rows), "source_counts": sources,
            "reviewed": reviewed,
            "result_keys": sorted(result.keys()),
            "sample_keys": sorted(rows[0].keys()) if rows else [],
        }, sort_keys=True))
        return
    if phase == "nuance_default":
        code, result = _request("POST", f"/v1/default/banks/{BANK}/reflect", {
            "query": "What did Ray historically confirm about Trial Gate and "
            "The Magician's Universal Aid tag? Explain whether Guardian Locked "
            "was confirmed as The Gate's second tag and whether these old "
            "choices are known to apply today.",
            "budget": "low", "max_tokens": 700,
        })
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError(f"default nuance reflection failed: HTTP {code}")
        answer = str(result.get("text", "")).lower()
        flags = {
            "trial_gate": "trial gate" in answer,
            "universal_aid": "universal aid" in answer,
            "guardian_locked": "guardian locked" in answer,
            "uncertainty": any(word in answer for word in
                               ("ambiguous", "unresolved", "unclear",
                                "not confirmed")),
            "present_applicability": any(word in answer for word in
                                         ("current", "today", "present")),
        }
        print("HINDSIGHT_PROBE:" + json.dumps({"phase": phase, **flags},
                                             sort_keys=True))
        if not all(flags.values()):
            raise RuntimeError("default reflection lost required nuance")
        return
    if phase == "nuance_diagnostic":
        for label, query in (
            ("combined", "What did I actually confirm about Trial Gate and "
             "The Magician's Universal Aid tag, and what remains uncertain?"),
            ("second_tag", "What was the status of Guardian Locked as The "
             "Gate's second tag? Was Ray's confirmation ambiguous?"),
        ):
            code, result = _request("POST", _memory_path("/recall"), {
                "query": query, "budget": "low", "max_tokens": 3500,
                "types": ["observation", "world", "experience"],
            })
            if code != 200 or not isinstance(result, dict) or not isinstance(
                result.get("results"), list
            ):
                raise RuntimeError("nuance recall unavailable")
            facts = [str(entry.get("text", "")).lower()
                     for entry in result["results"] if isinstance(entry, dict)]
            print("HINDSIGHT_PROBE:" + json.dumps({
                "phase": phase, "query": label, "facts": len(facts),
                "trial_gate": sum("trial gate" in fact for fact in facts),
                "universal_aid": sum("universal aid" in fact for fact in facts),
                "guardian_locked": sum("guardian locked" in fact for fact in facts),
                "uncertainty": sum(any(word in fact for word in
                                       ("ambiguous", "unresolved", "unclear",
                                        "not confirmed")) for fact in facts),
                "historical": sum("historical" in fact for fact in facts),
                "source_id": sum("source record id" in fact for fact in facts),
            }, sort_keys=True))
        code, result = _request("POST", f"/v1/default/banks/{BANK}/reflect", {
            "query": "What did Ray historically confirm about Trial Gate and "
            "The Magician's Universal Aid tag? Explain whether Guardian Locked "
            "was confirmed as The Gate's second tag and whether these old "
            "choices are known to apply today.",
            "budget": "low",
            "max_tokens": 700,
            "reflect_search_observations_max_tokens": 2500,
            "reflect_search_observations_include_entities": False,
        })
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError("nuance reflection unavailable")
        answer = str(result.get("text", "")).lower()
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "query": "reflection",
            "trial_gate": "trial gate" in answer,
            "universal_aid": "universal aid" in answer,
            "guardian_locked": "guardian locked" in answer,
            "uncertainty": any(word in answer for word in
                               ("ambiguous", "unresolved", "unclear",
                                "not confirmed")),
            "present_applicability": any(word in answer for word in
                                         ("current", "today", "present")),
        }, sort_keys=True))
        return
    if phase == "backfill_inventory":
        code, result = _request("GET", f"/v1/default/banks/{BANK}/documents?limit=100")
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError(f"backfill inventory failed: HTTP {code}")
        entries = next((result[key] for key in ("documents", "items", "results")
                        if isinstance(result.get(key), list)), None)
        if entries is None:
            raise RuntimeError("backfill inventory shape differs")
        ids = [entry.get("id", entry.get("document_id")) for entry in entries
               if isinstance(entry, dict)]
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase,
            "total": result.get("total", len(ids)),
            "reviewed": sum(isinstance(i, str) and i.startswith("lucy-reviewed:")
                            for i in ids),
            "chatgpt": sum(isinstance(i, str) and i.startswith("lucy-chatgpt:")
                           for i in ids),
            "chatgpt_document_ids": sorted(i for i in ids if isinstance(i, str)
                                           and i.startswith("lucy-chatgpt:")),
        }))
        return
    if phase == "reviewed_full":
        code, result = _request("GET", f"/v1/default/banks/{BANK}/documents?limit=100")
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError(f"reviewed full inventory failed: HTTP {code}")
        entries = next((result[key] for key in ("documents", "items", "results")
                        if isinstance(result.get(key), list)), None)
        if entries is None:
            raise RuntimeError("reviewed full inventory shape differs")
        ids = [entry.get("id", entry.get("document_id")) for entry in entries
               if isinstance(entry, dict)]
        reviewed = sum(isinstance(i, str) and i.startswith("lucy-reviewed:") for i in ids)
        chatgpt = sum(isinstance(i, str) and i.startswith("lucy-chatgpt:") for i in ids)
        if (result.get("total", len(ids)) != 64 or reviewed != 32 or chatgpt != 32):
            raise RuntimeError("reviewed full inventory differs")
        recalled = _recall_text(_recall("What did Ray confirm about Trial Gate and "
                                        "The Magician's Universal Aid tag?"))
        if "trial gate" not in recalled or "universal aid" not in recalled:
            raise RuntimeError("reviewed Gate/Magician recall is unavailable")
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "reviewed": reviewed, "chatgpt": chatgpt,
            "gate_and_magician_recalled": True,
        }))
        return
    if phase == "reviewed_three":
        code, result = _request("GET", f"/v1/default/banks/{BANK}/documents?limit=100")
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError(f"reviewed document inventory failed: HTTP {code}")
        entries = next((result[key] for key in ("documents", "items", "results")
                        if isinstance(result.get(key), list)), None)
        if entries is None:
            raise RuntimeError("reviewed document inventory shape differs")
        expected = {
            "lucy-reviewed:9263c5f6-1cfe-581c-b038-96abcea82384:v2",
            "lucy-reviewed:a2f5788d-a662-5186-a65e-18e19c58d0c1:v2",
            "lucy-reviewed:c8618f70-7d75-5afd-becb-67e7c400f5e3:v2",
        }
        ids = {entry.get("id", entry.get("document_id"))
               for entry in entries if isinstance(entry, dict)}
        if ids != expected or result.get("total", len(entries)) != 3:
            raise RuntimeError("reviewed document inventory differs")
        recalled = _recall_text(_recall("What did Ray say about Trial Gate and "
                                         "Universal Aid as the Magician's tag?"))
        if "trial gate" not in recalled or "universal aid" not in recalled:
            raise RuntimeError("reviewed Gate and Magician memories were not both recalled")
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "document_count": 3,
            "gate_and_magician_recalled": True,
        }))
        return
    if phase == "clear_synthetic":
        code, result = _request("GET", f"/v1/default/banks/{BANK}/documents?limit=100")
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError(f"synthetic bank inventory failed: HTTP {code}")
        entries = next((result[key] for key in ("documents", "items", "results")
                        if isinstance(result.get(key), list)), None)
        if entries is None:
            raise RuntimeError("synthetic bank inventory shape differs")
        identifiers = {entry.get("id", entry.get("document_id"))
                       for entry in entries if isinstance(entry, dict)}
        if (len(entries) != len(identifiers)
                or result.get("total", len(entries)) != len(entries)
                or identifiers - {DOC_A, DOC_B}):
            raise RuntimeError("synthetic bank contains unexpected documents")
        deleted, _ = _request("DELETE", f"/v1/default/banks/{BANK}")
        if deleted not in {200, 204}:
            raise RuntimeError(f"synthetic bank cleanup failed: HTTP {deleted}")
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "synthetic_documents_removed": len(identifiers),
        }))
        return
    if phase == "reflect_only":
        code, result = _request(
            "POST", f"/v1/default/banks/{BANK}/reflect",
            {"query": "Where is Iris's synthetic copper notebook after the cabinet moved?"},
        )
        if code != 200 or not isinstance(result, dict):
            raise RuntimeError(f"synthetic reflection failed: HTTP {code}")
        answer = str(result.get("text", "")).lower()
        if not all(part in answer for part in ("iris", "notebook", "blue")):
            raise RuntimeError("synthetic reflection omitted the related memories")
        print("HINDSIGHT_PROBE:" + json.dumps({"phase": phase, "reflected": True}))
        return
    if phase in {"synthetic", "correct_delete"}:
        if phase == "synthetic":
            _retain_and_reflect()
        _correct_and_delete()
        print("HINDSIGHT_PROBE:" + json.dumps({
            "phase": phase, "health": True, "unauthorized_denied": True,
            "corrected_recalled": True, "deleted_document_absent": True,
        }, sort_keys=True))
        return
    recovered = _recall_text(_recall("Which cabinet contains Iris's synthetic copper notebook?"))
    if "east" not in recovered:
        raise RuntimeError("synthetic memory not recalled after restart")
    print("HINDSIGHT_PROBE:" + json.dumps({"phase": phase,
                                           "recalled_after_restart": True}))


def _retain_and_reflect() -> None:
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
def _correct_and_delete() -> None:
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


if __name__ == "__main__":
    main()
