"""Read-only verification of a quarantined private-memory realm schema head."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from lucy.readiness import PRIVATE_MEMORY_SCHEMA_REVISION

AUTHORIZATION = "private-memory-head-read-only-v1.3"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
ALL_CHECKS = "all"
CHECK_NAMES = (
    "revision",
    "runtime_admission",
    "lifecycle",
    "capture_boundary",
    "content_scope",
    "service_binding",
)


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerificationConfiguration:
    database_url: URL
    content_scope_id: UUID

    @classmethod
    def from_environment(
        cls, values: Mapping[str, str] | None = None
    ) -> VerificationConfiguration:
        environment = os.environ if values is None else values
        if (
            environment.get("RENDER") != "true"
            or environment.get("LUCY_ENVIRONMENT") != "production"
            or environment.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
            or environment.get("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
            or environment.get("LUCY_REALM_HEAD_VERIFICATION_AUTHORIZATION")
            != AUTHORIZATION
        ):
            raise VerificationError("private-memory head verification gate failed")
        try:
            url = make_url(environment["LUCY_MIGRATION_DATABASE_URL"])
            scope = UUID(environment["LUCY_CONTENT_SCOPE_ID"])
        except (KeyError, ValueError):
            raise VerificationError(
                "private-memory head verification configuration is invalid"
            ) from None
        if (
            url.drivername not in {"postgresql", "postgresql+psycopg"}
            or url.username != "lucy_migration"
            or not url.password
            or _PRIVATE_RENDER_HOST.fullmatch(url.host or "") is None
            or url.port not in {None, 5432}
            or not (url.database or "").startswith("lucy_")
            or url.query.get("sslmode") != "require"
        ):
            raise VerificationError(
                "private-memory head verification database boundary is invalid"
            )
        return cls(url.set(drivername="postgresql+psycopg"), scope)


def _selected_checks(check: str) -> tuple[str, ...]:
    if check == ALL_CHECKS:
        return CHECK_NAMES
    if check not in CHECK_NAMES:
        raise VerificationError("private-memory head verification check is invalid")
    return (check,)


def _check_sql(check: str) -> tuple[str, Mapping[str, object]]:
    if check == "revision":
        return (
            "SELECT (SELECT version_num FROM public.alembic_version) = :expected",
            {"expected": PRIVATE_MEMORY_SCHEMA_REVISION},
        )
    if check == "runtime_admission":
        return (
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton) "
            "= 'quarantined'",
            {},
        )
    if check == "lifecycle":
        return (
            "SELECT (SELECT state FROM lucy.lifecycle WHERE singleton) = 'offline'",
            {},
        )
    if check == "capture_boundary":
        return "SELECT lucy.capture_boundary_safe_v1()", {}
    if check == "content_scope":
        return (
            "SELECT (SELECT count(*) FROM lucy.realm_content_scopes_v1 "
            "WHERE id=:scope) = 1",
            {},
        )
    if check == "service_binding":
        return (
            "SELECT (SELECT count(*) FROM lucy.realm_service_bindings_v1 "
            "WHERE content_scope_id=:scope AND active) = 1",
            {},
        )
    raise VerificationError("private-memory head verification check is invalid")


def _requested_check(argv: Sequence[str]) -> str:
    arguments = list(argv)
    if not arguments:
        check = ALL_CHECKS
    elif len(arguments) == 2 and arguments[0] == "--check":
        check = arguments[1]
    else:
        raise VerificationError("verification utility arguments are invalid")
    _selected_checks(check)
    return check


def verify(
    configuration: VerificationConfiguration, *, check: str = ALL_CHECKS
) -> dict[str, object]:
    selected = _selected_checks(check)
    engine = create_engine(configuration.database_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text("SET TRANSACTION READ ONLY"))
                for name in selected:
                    statement, parameters = _check_sql(name)
                    bound = {"scope": configuration.content_scope_id, **parameters}
                    if connection.execute(text(statement), bound).scalar_one() is not True:
                        raise VerificationError(
                            f"private-memory realm check failed: {name}"
                        )
            finally:
                transaction.rollback()
    finally:
        engine.dispose()
    return {
        "contract": "lucy.private-memory-head-verification.v1.3",
        "status": "passed",
        "checks": list(selected),
        "transcript_capture_enabled": False,
        "product_ingress_enabled": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        check = _requested_check(sys.argv[1:] if argv is None else argv)
        report = verify(VerificationConfiguration.from_environment(), check=check)
    except VerificationError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
