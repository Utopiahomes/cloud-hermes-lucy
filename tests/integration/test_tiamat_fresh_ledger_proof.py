"""Gate 2 proof 1: a fresh ledger provisioned the way Render is, then the whole ceremony.

On a brand-new PostgreSQL 16 cluster with TLS, and a non-superuser owner that can create roles
(the shape of Render's managed owner), this runs the real provisioning commands in the order the
deployment sequence gives them: the bootstrap (roles, template, migration to 0006), the owner's
migration to head, the day-zero initialization, the D1 finalizer, the capability check and the
schema-tolerant readback. Then every Phase B ceremony command runs on that ledger, as its own
recovery login, through the launcher's claimant and the partition: nothing is seeded around the
provisioning, and only the AWS transport is simulated.

Opt-in: ``TIAMAT_FRESH_ADMIN_URL`` names a superuser on a throwaway local cluster (host
localhost or 127.0.0.1 only) that has never held the Tiamat roles; they are cluster-global.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from sqlalchemy.engine import make_url

from tests.integration.test_tiamat_gate2_operator_cli import _run, _script, run_phase_b_ceremony

ROOT = Path(__file__).resolve().parents[2]
DATABASE = "tiamat_fresh"
OWNER = "tiamat_fresh_owner"


def _admin_url() -> str:
    url = os.environ.get("TIAMAT_FRESH_ADMIN_URL", "")
    if not url:
        pytest.skip("TIAMAT_FRESH_ADMIN_URL is not configured")
    if make_url(url).host not in {"localhost", "127.0.0.1"}:
        pytest.fail("the fresh-ledger proof runs only on a local throwaway cluster", pytrace=False)
    return url


def test_a_fresh_ledger_provisions_to_head_and_completes_the_ceremony(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(relative: str, *args: str) -> dict[str, Any]:
        return _run(capsys, monkeypatch, relative, *args)

    admin = make_url(_admin_url())
    owner_password = token_urlsafe(32)
    with psycopg.connect(
        admin.set(drivername="postgresql").render_as_string(hide_password=False), autocommit=True
    ) as connection:
        taken = connection.execute(
            "SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname LIKE 'tiamat%%'"
        ).fetchone()
        if taken is None or int(taken[0]) != 0:
            pytest.skip("the cluster already holds Tiamat roles; the proof needs a fresh cluster")
        # Render's managed owner: a login that owns the database and can create roles, but is
        # not a superuser and cannot bypass row-level security.
        connection.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION "
                "NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(OWNER), sql.Literal(owner_password))
        )
        connection.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(DATABASE), sql.Identifier(OWNER)
            )
        )
    owner_url = (
        admin.set(
            drivername="postgresql", username=OWNER, password=owner_password, database=DATABASE
        )
        .update_query_dict({"sslmode": "require"})
        .render_as_string(hide_password=False)
    )
    runtime_password, recovery_password = token_urlsafe(32), token_urlsafe(32)
    recovery_url = (
        make_url(owner_url)
        .set(username="tiamat_recovery", password=recovery_password)
        .render_as_string(hide_password=False)
    )
    monkeypatch.syspath_prepend(str(ROOT / "deploy" / "postgres"))

    # 2.2 The bootstrap: roles, the role template, migration to 0006, verified logins.
    monkeypatch.setenv("TIAMAT_ENVIRONMENT", "staging")
    monkeypatch.setenv("TIAMAT_BOOTSTRAP_DATABASE_URL", owner_url)
    monkeypatch.setenv("TIAMAT_RUNTIME_PASSWORD", runtime_password)
    monkeypatch.setenv("TIAMAT_RECOVERY_PASSWORD", recovery_password)
    bootstrapped = run(
        "deploy/postgres/bootstrap_tiamat_staging_v1.py",
        "--confirm-bootstrap",
        f"bootstrap:staging:{DATABASE}",
    )
    assert bootstrapped["migration_head"] == "0006_render_recovery_rls"
    for name in (
        "TIAMAT_BOOTSTRAP_DATABASE_URL",
        "TIAMAT_RUNTIME_PASSWORD",
        "TIAMAT_RECOVERY_PASSWORD",
    ):
        monkeypatch.delenv(name)

    # 2.3 The owner migrates the Tiamat lineage to head.
    migrated = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "tiamat_alembic.ini", "upgrade", "head"],
        cwd=str(ROOT),
        env={**os.environ, "TIAMAT_MIGRATION_DATABASE_URL": owner_url},
        check=False,
        capture_output=True,
        text=True,
    )
    assert migrated.returncode == 0, migrated.stderr[-2000:]

    # 2.5 Day-zero initialization, blocked at generation 1, as the recovery login.
    storage_epoch = uuid4()
    monkeypatch.setenv("TIAMAT_RECOVERY_DATABASE_URL", recovery_url)
    day_zero = run(
        "deploy/postgres/initialize_tiamat_ledger_v1.py",
        "--environment", "staging",
        "--storage-epoch", str(storage_epoch),
        "--recovery-generation", "1",
        "--confirm-initialize", f"initialize:staging:{storage_epoch}",
    )  # fmt: skip
    ledger_id = UUID(str(day_zero["ledger_id"]))
    checkpoint = tmp_path / "day-zero.json"
    checkpoint.write_text(json.dumps(day_zero), encoding="utf-8")

    # 2.4 The D1 finalizer on the blocked ledger, as the owner.
    monkeypatch.setenv("TIAMAT_MIGRATION_DATABASE_URL", owner_url)
    finalize = [
        "deploy/postgres/finalize_tiamat_d1_v1.py",
        "--environment", "staging",
        "--expected-ledger-id", str(ledger_id),
        "--confirm-blocked-ledger", f"finalize-d1:staging:{ledger_id}",
    ]  # fmt: skip
    monkeypatch.setattr(sys, "argv", finalize)
    _script("deploy/postgres/finalize_tiamat_d1_v1.py").main()
    assert "D1 role finalization completed" in capsys.readouterr().out
    monkeypatch.delenv("TIAMAT_MIGRATION_DATABASE_URL")

    # 2.6 Capability check and readback, as the recovery login.
    capabilities = run(
        "deploy/postgres/verify_tiamat_render_capabilities_v1.py", "--environment", "staging"
    )
    assert capabilities
    readback = run(
        "deploy/postgres/tiamat_reconciliation_ledger_v1.py", "readback", "--environment", "staging"
    )
    assert readback["login"] == "tiamat_recovery"
    assert readback["schema_revision"] == "0017_revocation_generation"
    assert readback["ledger_id"] == str(ledger_id)
    assert readback["gate_columns_missing"] == []
    gate = readback["gate"]
    assert (gate["recovery_generation"], gate["dispatch_blocked"]) == (1, True)
    assert gate["block_reason"] == "initial_reconciliation_required"
    tables = readback["tables"]
    assert all(
        entry.get("environment_rows", 0) == 0
        for name, entry in tables.items()
        if name != "restore_gate"
    )

    # Sections 3-4 and 7.3-7.8: the whole ceremony on this ledger, then the claimant.
    final = run_phase_b_ceremony(
        run,
        monkeypatch,
        tmp_path,
        environment="staging",
        ledger_id=ledger_id,
        storage_epoch=storage_epoch,
        recovery_url=recovery_url,
        day_zero_checkpoint=checkpoint,
    )
    assert (final["dispatch_blocked"], final["recovery_generation"]) == (False, 2)
    assert final["anchor_floor"]["transition_version"] == 3

    evidence_path = os.environ.get("TIAMAT_FRESH_EVIDENCE_PATH")
    if evidence_path:
        with psycopg.connect(
            admin.set(drivername="postgresql").render_as_string(hide_password=False)
        ) as connection:
            server = connection.execute("SHOW server_version").fetchone()
        Path(evidence_path).write_text(
            json.dumps(
                {
                    "server_version": None if server is None else str(server[0]),
                    "bootstrap": bootstrapped,
                    "day_zero_checkpoint": day_zero,
                    "capabilities": capabilities,
                    "readback_after_provisioning": readback,
                    "report_after_ceremony": final,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
