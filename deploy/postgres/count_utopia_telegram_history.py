"""Content-free Utopia Telegram history inventory before Raymond bot cutover."""

from __future__ import annotations

import json
import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

AUTHORIZATION = "utopia-telegram-history-metadata-before-raymond-cutover-v1"


def main() -> int:
    if (
        os.getenv("RENDER") != "true"
        or os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_HISTORY_COUNT_AUTHORIZATION") != AUTHORIZATION
    ):
        raise RuntimeError("history inventory environment is invalid")
    url = make_url(os.environ["LUCY_DATABASE_URL"])
    owner_chat_id = os.environ["LUCY_OWNER_CHAT_ID"]
    if not owner_chat_id.isdecimal() or not 1 <= len(owner_chat_id) <= 20:
        raise RuntimeError("owner chat identity is invalid")
    if (
        url.host != "dpg-daca8gafngtc73clvafg-a"
        or url.database != "lucy_6tns"
        or url.username != "lucy_migration"
        or not url.password
    ):
        raise RuntimeError("Utopia database boundary changed")
    engine = create_engine(
        url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)
    )
    with engine.connect() as connection:
        database, login = connection.execute(
            text("SELECT current_database(),session_user")
        ).one()
        if database != "lucy_6tns" or login != "lucy_migration":
            raise RuntimeError("Utopia database identity changed")
        rows = connection.execute(text("""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE status = 'committed') AS committed,
                   count(DISTINCT source_conversation_id) AS conversations,
                   count(user_evidence_id) AS user_links,
                   count(assistant_evidence_id) AS assistant_links
              FROM lucy.conversation_turns
             WHERE platform = 'telegram'
        """)).mappings().one()
        captures = connection.execute(text("""
            SELECT count(*) AS receipts,
                   count(*) FILTER (WHERE capture_enabled) AS retained_receipts
              FROM lucy.capture_receipts
             WHERE platform = 'telegram'
        """)).mappings().one()
        evidence = connection.execute(text("""
            SELECT count(*) AS telegram_evidence,
                   count(*) FILTER (WHERE p.evidence_id IS NOT NULL) AS encrypted_payloads,
                   count(*) FILTER (WHERE t.evidence_id IS NOT NULL) AS tombstones
              FROM lucy.evidence e
              LEFT JOIN lucy.evidence_payloads p ON p.evidence_id = e.id
              LEFT JOIN lucy.evidence_tombstones t ON t.evidence_id = e.id
             WHERE e.source = 'hermes'
               AND e.source_conversation_id LIKE 'telegram:%'
        """)).mappings().one()
        targets = connection.execute(text("""
            SELECT e.id::text AS evidence_id,
                   p.evidence_id IS NOT NULL AS has_payload,
                   t.evidence_id IS NOT NULL AS tombstoned,
                   EXISTS (
                       SELECT 1 FROM lucy.conversation_turns ct
                        WHERE ct.platform = 'telegram'
                          AND (ct.user_evidence_id = e.id
                               OR ct.assistant_evidence_id = e.id)
                   ) AS linked_turn
              FROM lucy.evidence e
              LEFT JOIN lucy.evidence_payloads p ON p.evidence_id = e.id
              LEFT JOIN lucy.evidence_tombstones t ON t.evidence_id = e.id
             WHERE e.source = 'hermes'
               AND e.source_conversation_id LIKE 'telegram:%'
             ORDER BY e.id
        """)).mappings().all()
        scoped = connection.execute(text("""
            SELECT count(*) AS owner_conversation_evidence,
                   count(*) FILTER (WHERE p.evidence_id IS NOT NULL) AS payloads,
                   count(*) FILTER (WHERE w.evidence_id IS NOT NULL) AS current_wrappers,
                   count(*) FILTER (WHERE f.evidence_id IS NOT NULL) AS deletion_fences
              FROM lucy.scoped_evidence_records_v2 e
              LEFT JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id = e.id
              LEFT JOIN lucy.scoped_evidence_wrappers_v2 w
                ON w.evidence_id = e.id AND w.current
              LEFT JOIN lucy.scoped_evidence_deletion_fences_v2 f
                ON f.evidence_id = e.id
             WHERE e.content_classification = 'owner_conversation'
        """)).mappings().one()
        scoped_targets = connection.execute(text("""
            SELECT e.id::text AS evidence_id, e.status,
                   e.created_at::date::text AS created_date,
                   p.evidence_id IS NOT NULL AS has_payload,
                   w.wrapped_key_ref::text AS wrapped_key_ref,
                   f.evidence_id IS NOT NULL AS deletion_fenced,
                   o.state AS deletion_operation_state,
                   i.source_conversation_id LIKE 'cloud-acceptance-%%' AS acceptance_probe
              FROM lucy.scoped_evidence_records_v2 e
              JOIN lucy.scoped_archive_intents_v1 i ON i.evidence_id = e.id
              LEFT JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id = e.id
              LEFT JOIN lucy.scoped_evidence_wrappers_v2 w
                ON w.evidence_id = e.id AND w.current
              LEFT JOIN lucy.scoped_evidence_deletion_fences_v2 f
                ON f.evidence_id = e.id
              LEFT JOIN lucy.sensitive_operations_v2 o ON o.id = f.operation_id
             WHERE e.content_classification = 'owner_conversation'
             ORDER BY e.id
        """)).mappings().all()
        scoped_receipts = connection.execute(text("""
            SELECT count(*) AS receipts,
                   count(*) FILTER (WHERE capture_enabled) AS retained_receipts
              FROM lucy.scoped_capture_receipts_v1
             WHERE platform = 'telegram'
        """)).mappings().one()
        owner_legacy = connection.execute(text("""
            SELECT count(*) AS evidence,
                   count(*) FILTER (WHERE p.evidence_id IS NOT NULL) AS live_payloads,
                   count(*) FILTER (WHERE t.evidence_id IS NOT NULL) AS tombstones
              FROM lucy.evidence e
              LEFT JOIN lucy.evidence_payloads p ON p.evidence_id = e.id
              LEFT JOIN lucy.evidence_tombstones t ON t.evidence_id = e.id
             WHERE e.source = 'hermes'
               AND e.source_conversation_id = 'telegram:' || :chat_id
        """), {"chat_id": owner_chat_id}).mappings().one()
        owner_legacy_targets = connection.execute(text("""
            SELECT e.id::text AS evidence_id,
                   p.evidence_id IS NOT NULL AS has_payload,
                   p.key_ref::text AS wrapped_key_ref,
                   t.evidence_id IS NOT NULL AS tombstoned
              FROM lucy.evidence e
              LEFT JOIN lucy.evidence_payloads p ON p.evidence_id = e.id
              LEFT JOIN lucy.evidence_tombstones t ON t.evidence_id = e.id
             WHERE e.source = 'hermes'
               AND e.source_conversation_id = 'telegram:' || :chat_id
             ORDER BY e.id
        """), {"chat_id": owner_chat_id}).mappings().all()
        owner_scoped = connection.execute(text("""
            SELECT count(*) AS evidence,
                   count(*) FILTER (WHERE p.evidence_id IS NOT NULL) AS live_payloads,
                   count(*) FILTER (WHERE w.evidence_id IS NOT NULL) AS current_wrappers,
                   count(*) FILTER (WHERE f.evidence_id IS NOT NULL) AS deletion_fences
              FROM lucy.scoped_archive_intents_v1 i
              JOIN lucy.scoped_evidence_records_v2 e ON e.id = i.evidence_id
              LEFT JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id = e.id
              LEFT JOIN lucy.scoped_evidence_wrappers_v2 w
                ON w.evidence_id = e.id AND w.current
              LEFT JOIN lucy.scoped_evidence_deletion_fences_v2 f
                ON f.evidence_id = e.id
             WHERE i.source_conversation_id = :chat_id
               AND i.content_classification = 'owner_conversation'
        """), {"chat_id": owner_chat_id}).mappings().one()
        owner_scoped_targets = connection.execute(text("""
            SELECT e.id::text AS evidence_id, e.status,
                   p.evidence_id IS NOT NULL AS has_payload,
                   w.wrapped_key_ref::text AS wrapped_key_ref,
                   f.evidence_id IS NOT NULL AS deletion_fenced,
                   o.state AS deletion_operation_state
              FROM lucy.scoped_archive_intents_v1 i
              JOIN lucy.scoped_evidence_records_v2 e ON e.id = i.evidence_id
              LEFT JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id = e.id
              LEFT JOIN lucy.scoped_evidence_wrappers_v2 w
                ON w.evidence_id = e.id AND w.current
              LEFT JOIN lucy.scoped_evidence_deletion_fences_v2 f
                ON f.evidence_id = e.id
              LEFT JOIN lucy.sensitive_operations_v2 o ON o.id = f.operation_id
             WHERE i.source_conversation_id = :chat_id
               AND i.content_classification = 'owner_conversation'
             ORDER BY e.id
        """), {"chat_id": owner_chat_id}).mappings().all()
        legacy_acceptance = connection.execute(text("""
            SELECT count(*) AS evidence,
                   count(*) FILTER (WHERE p.evidence_id IS NOT NULL) AS live_payloads
              FROM lucy.evidence e
              LEFT JOIN lucy.evidence_payloads p ON p.evidence_id = e.id
             WHERE e.source = 'hermes'
               AND e.source_conversation_id LIKE 'telegram:cloud-acceptance-%%'
        """)).mappings().one()
    print(json.dumps({
        "status": "passed",
        "database": database,
        "turns": dict(rows),
        "captures": dict(captures),
        "evidence": dict(evidence),
        "targets": [dict(row) for row in targets],
        "scoped": dict(scoped),
        "scoped_targets": [dict(row) for row in scoped_targets],
        "scoped_receipts": dict(scoped_receipts),
        "owner_legacy": dict(owner_legacy),
        "owner_legacy_targets": [dict(row) for row in owner_legacy_targets],
        "owner_scoped": dict(owner_scoped),
        "owner_scoped_targets": [dict(row) for row in owner_scoped_targets],
        "legacy_acceptance": dict(legacy_acceptance),
        "content_read": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
