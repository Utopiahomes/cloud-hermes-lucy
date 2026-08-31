"""Run in the pinned Hermes image with --network none; all Lucy I/O is synthetic."""

from __future__ import annotations

import importlib.util
import json
import sys
from contextvars import Context
from typing import Any

from hermes_cli.middleware import _run_execution_chain
from hermes_cli.plugins import PluginManager
from tools.registry import ToolRegistry


def main() -> None:
    spec = importlib.util.spec_from_file_location("lucy_control_probe", sys.argv[1])
    assert spec is not None and spec.loader is not None
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    evidence_id = "12345678-1234-5678-9234-567812345678"
    claim_id = "87654321-4321-6789-9321-678943216789"
    disclosures: list[tuple[str, str]] = []
    archived_replies: list[tuple[str, str]] = []
    lookup_sources = {"A": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                      "B": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}

    def archive(**kwargs: Any) -> dict[str, Any]:
        if kwargs["role"] == "assistant":
            archived_replies.append((kwargs["session_id"], kwargs["turn_id"]))
            assert plugin._SESSION_TURN[kwargs["session_id"]]["source_evidence_ids"] == {
                lookup_sources[kwargs["session_id"]], evidence_id,
            }
        return {"archived": True, "evidence_id": evidence_id, "turn_committed": True}

    def permit(**kwargs: Any) -> dict[str, Any]:
        disclosures.append((kwargs["session_id"], kwargs["turn_id"]))
        return {"synthetic": True}

    plugin._accept_turn = lambda *_: True
    plugin._archive_conversation_message = archive
    plugin._issue_sensitive_permit = permit
    plugin._request_boundary_json = lambda *_a, **_k: {
        "audited": True, "autonomous": True,
        "message": {"role": "user", "content": "Synthetic exact wording"},
    }
    plugin._request_json = lambda _path, **kwargs: {
        "read_only": True, "claims": [{"object": "Synthetic retrieved memory",
            "source_evidence_ids": [lookup_sources[kwargs["payload"]["query"]]]}],
    }
    registry = ToolRegistry()
    registry.register(name="lucy_evidence_retrieve", toolset="lucy_probe",
                      schema=plugin.EVIDENCE_RETRIEVE_SCHEMA, handler=plugin._evidence_retrieve)
    registry.register(name="lucy_memory_lookup", toolset="lucy_probe",
                      schema=plugin.MEMORY_LOOKUP_SCHEMA, handler=plugin._memory_lookup)
    args = {"evidence_id": evidence_id, "claim_id": claim_id, "reason": "resolve_ambiguity",
            "session_id": "FORGED", "turn_id": "FORGED"}
    contexts = {session: Context() for session in ("A", "B")}
    for session, context in contexts.items():
        context.run(PluginManager._invoke_hook_callback, plugin._pre_llm_call, {
            "platform": "telegram", "session_id": session, "turn_id": f"turn-{session}",
            "user_message": "Synthetic test input",
        })
    for session, context in contexts.items():
        looked_up = context.run(
            _run_execution_chain, "tool_execution", [plugin._tool_execution_middleware],
            lambda values, sid=session: registry.dispatch(
                "lucy_memory_lookup", values, session_id=sid,
            ),
            args={"query": session, "source_evidence_ids": ["FORGED"]},
            tool_name="lucy_memory_lookup", session_id=session, turn_id=f"turn-{session}",
        )
        assert json.loads(looked_up)["ok"]
        result = context.run(
            _run_execution_chain, "tool_execution", [plugin._tool_execution_middleware],
            # Exact model_tools.py dispatch shape: session_id, but no turn_id.
            lambda values, sid=session: registry.dispatch(
                "lucy_evidence_retrieve", values, session_id=sid,
            ),
            args=args, tool_name="lucy_evidence_retrieve", session_id=session,
            turn_id=f"turn-{session}",
        )
        assert json.loads(result)["ok"]
        assert context.run(plugin._TOOL_CONTEXT.get) is None
        result = context.run(PluginManager._invoke_hook_callback, plugin._transform_llm_output, {
            # Exact turn_finalizer.py hook shape: session_id, but no turn_id.
            "platform": "telegram", "session_id": session, "response_text": "Synthetic reply",
        })
        assert result is None
    assert disclosures == [("A", "turn-A"), ("B", "turn-B")]
    assert archived_replies == disclosures
    assert not json.loads(registry.dispatch("lucy_evidence_retrieve", args, session_id="A"))["ok"]
    print(json.dumps({"pinned_middleware_and_registry": "passed", "turn_binding": "passed",
                      "observed_source_provenance": "passed",
                      "output_hook": "passed", "network": "disabled", "cloud_calls": 0}))


if __name__ == "__main__":
    main()
