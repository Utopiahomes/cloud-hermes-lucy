"""Render the Tiamat role SQL for one explicit PostgreSQL database identifier.

This tool emits SQL only. It never accepts, generates, logs, or persists credentials.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "deploy" / "postgres" / "tiamat_roles.sql.example"
DATABASE_TOKEN = "__TIAMAT_DATABASE__"
DATABASE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def render_role_template(database_name: str) -> str:
    """Return role SQL bound to one safe, exact, unquoted database identifier."""
    if DATABASE_IDENTIFIER.fullmatch(database_name) is None:
        raise ValueError(
            "database name must be a lowercase PostgreSQL identifier of at most 63 bytes"
        )

    template = TEMPLATE.read_text(encoding="utf-8")
    if template.count(DATABASE_TOKEN) != 1:
        raise ValueError("role template must contain exactly one database placeholder")
    return template.replace(DATABASE_TOKEN, database_name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-name", required=True)
    args = parser.parse_args()
    print(render_role_template(args.database_name), end="")


if __name__ == "__main__":
    main()
