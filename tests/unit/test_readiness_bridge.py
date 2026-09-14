from lucy.readiness import _v13_required_functions


def _required(mode: str, revision: str, *, conversation: bool = False) -> set[str]:
    return set(
        _v13_required_functions(
            mode=mode,
            schema_revision=revision,
            public_conversation_enabled=conversation,
            telegram_stage2=True,
        )
    )


def test_stage2_bridge_requires_only_functions_present_at_0054() -> None:
    routine = _required("routine", "0054_stage2_scoped_turn_commit")
    policy = _required("policy", "0054_stage2_scoped_turn_commit")

    assert "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint)" in routine
    assert "lucy.stage_memory_import_candidate_v1(jsonb)" not in routine
    assert "lucy.authorize_memory_import_campaign_v1(" not in "".join(policy)
    assert "lucy.commit_capturable_scoped_turn_v1(uuid,uuid)" in routine


def test_post_import_bridge_requires_governed_memory_functions() -> None:
    for revision in (
        "0056_memory_import_budget",
        "0057_public_conversation",
        "0068_workspaces_service_auth",
    ):
        routine = _required("routine", revision)
        policy = _required("policy", revision)

        assert "lucy.stage_memory_import_candidate_v1(jsonb)" in routine
        assert "lucy.reserve_memory_import_attempt_v1(uuid,text,bigint)" in routine
        assert "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint)" not in routine
        assert any(
            function.startswith("lucy.authorize_memory_import_campaign_v1(")
            for function in policy
        )


def test_public_bridge_switches_function_only_when_conversation_is_enabled() -> None:
    legacy = _required("public", "0054_stage2_scoped_turn_commit")
    conversation = _required(
        "public",
        "0057_public_conversation",
        conversation=True,
    )

    assert legacy == {"lucy.public_projection_answer_v2(text,text,uuid)"}
    assert conversation == {"lucy.public_projection_knowledge_v1(text,uuid)"}
