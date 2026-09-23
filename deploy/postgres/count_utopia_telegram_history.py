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
    print(json.dumps({
        "status": "passed",
        "database": database,
        "turns": dict(rows),
        "captures": dict(captures),
        "evidence": dict(evidence),
        "targets": [dict(row) for row in targets],
        "content_read": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
