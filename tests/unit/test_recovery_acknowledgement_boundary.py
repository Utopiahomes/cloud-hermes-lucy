from pathlib import Path

from lucy.readiness import R1_SCHEMA_REVISION, STAGE2_SCHEMA_REVISION

ROOT = Path(__file__).parents[2]


def test_ack_receiver_migration_grants_only_exact_pending_reads() -> None:
    source = (
        ROOT / "migrations" / "versions" / "0050_r1_recovery_ack_receiver.py"
    ).read_text(encoding="utf-8")
    assert R1_SCHEMA_REVISION == "0053_r1_telegram_authority"
    assert STAGE2_SCHEMA_REVISION == "0054_stage2_scoped_turn_commit"
    assert source.count("GRANT EXECUTE ON FUNCTION") == 2
    assert "get_pending_authority_event_v1(uuid)" in source
    assert "TO lucy_authority_recovery_writer" in source
    assert "get_pending_cost_event_v1(uuid)" in source
    assert "TO lucy_cost_recovery_writer" in source
    assert not any(
        authority in source
        for authority in (
            "GRANT SELECT",
            "GRANT INSERT",
            "GRANT UPDATE",
            "GRANT DELETE",
            "prepare_authority_event_v1",
            "prepare_cost_journal_event_v1",
        )
    )
