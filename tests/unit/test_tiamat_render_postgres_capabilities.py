from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]


class _Result:
    def __init__(self, row: dict[str, object]) -> None:
        self._row = row

    def fetchone(self) -> dict[str, object]:
        return self._row


class _Connection:
    def __init__(self, *, tls: bool = True) -> None:
        self.ledger_id = uuid4()
        self.storage_epoch = uuid4()
        self.tls = tls

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, params: object = None) -> _Result:
        del params
        normalized = " ".join(statement.split())
        if "current_user AS database_user" in normalized:
            return _Result(
                {
                    "database_user": "tiamat_recovery",
                    "server_version_num": 160004,
                    "transport_tls": self.tls,
                    "system_identifier": "734208541231",
                    "timeline_id": 1,
                    "flushed_wal_lsn": "0/12345AB",
                }
            )
        if "FROM tiamat.ledger_identity" in normalized:
            return _Result({"ledger_id": str(self.ledger_id)})
        if "FROM tiamat.restore_gate" in normalized:
            return _Result(
                {
                    "storage_epoch": str(self.storage_epoch),
                    "recovery_generation": 1,
                    "dispatch_blocked": True,
                }
            )
        raise AssertionError(f"unexpected SQL: {normalized}")


def _module() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "verify_tiamat_render_capabilities_v1.py"
    spec = importlib.util.spec_from_file_location("verify_tiamat_render_capabilities_v1", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_capability_probe_requires_tls_and_reads_continuity_beacon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    connection = _Connection()
    monkeypatch.setattr(module.psycopg, "connect", lambda *_args, **_kwargs: connection)

    report = module.verify_render_capabilities(
        database_url="postgresql://tiamat_recovery:secret@private/tiamat?sslmode=require",
        environment="staging",
        expected_recovery_login="tiamat_recovery",
    )

    assert report.ledger_id == str(connection.ledger_id)
    assert report.storage_epoch == str(connection.storage_epoch)
    assert report.transport_tls is True
    assert report.flushed_wal_lsn == "0/12345AB"


def test_capability_probe_rejects_non_tls_configuration() -> None:
    module = _module()

    with pytest.raises(module.CapabilityRejected, match="must require TLS"):
        module.verify_render_capabilities(
            database_url="postgresql://tiamat_recovery:secret@private/tiamat",
            environment="staging",
            expected_recovery_login="tiamat_recovery",
        )


def test_capability_probe_rejects_non_tls_server_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    connection = _Connection(tls=False)
    monkeypatch.setattr(module.psycopg, "connect", lambda *_args, **_kwargs: connection)

    with pytest.raises(module.CapabilityRejected, match="not TLS protected"):
        module.verify_render_capabilities(
            database_url="postgresql://tiamat_recovery:secret@private/tiamat?sslmode=require",
            environment="staging",
            expected_recovery_login="tiamat_recovery",
        )
