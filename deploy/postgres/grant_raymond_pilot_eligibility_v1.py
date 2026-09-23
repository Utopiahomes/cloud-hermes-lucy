"""Grant only Raymond's routine login the existing scoped source-eligibility function."""

import os

import psycopg
from sqlalchemy.engine import make_url


def main() -> None:
    if os.environ.get("RENDER") != "true" or os.environ.get("LUCY_ENVIRONMENT") != "production":
        raise RuntimeError("Raymond eligibility grant requires production Render")
    if os.environ.get("LUCY_RAYMOND_ELIGIBILITY_AUTHORIZATION") != (
        "grant-raymond-routine-memory-source-eligibility-v1"
    ):
        raise RuntimeError("Raymond eligibility grant authorization is not exact")
    raw = os.environ["LUCY_MIGRATION_DATABASE_URL"]
    url = make_url(raw)
    if (url.host, url.database, url.username) != (
        "dpg-dak5bqad0e5s73b2e3d0-a", "lucy_raymond", "lucy_migration"
    ):
        raise RuntimeError("Raymond eligibility grant database target changed")
    with psycopg.connect(raw.replace("postgresql+psycopg://", "postgresql://")) as connection:
        if connection.execute("SELECT current_user").fetchone()[0] != "lucy_migration":
            raise RuntimeError("Raymond eligibility grant requires migration owner")
        connection.execute(
            "GRANT EXECUTE ON FUNCTION lucy.require_memory_import_sources_v1(uuid,text,jsonb) "
            "TO lucy_raymond_routine"
        )
        granted = connection.execute(
            "SELECT has_function_privilege(%s,%s,%s)",
            (
                "lucy_raymond_routine",
                "lucy.require_memory_import_sources_v1(uuid,text,jsonb)",
                "EXECUTE",
            ),
        ).fetchone()
        if granted is None or granted[0] is not True:
            raise RuntimeError("Raymond routine eligibility grant did not take effect")
    print("Raymond routine eligibility grant verified")


if __name__ == "__main__":
    main()
