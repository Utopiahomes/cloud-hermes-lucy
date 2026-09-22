"""The online successor installer must remain preview-only without an exact confirmation."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest

from lucy.shared_execution.anchor_writer import (
    AnchorWriter,
    AnchorWriteRequest,
    AnchorWriteResult,
    WriterRoot,
)
from lucy.shared_execution.recovery_anchor import RecoveryAnchorRejected
from lucy.shared_execution.recovery_anchor_commissioning import (
    verify_continued_quarantine_successor_package,
)
from tests.unit.test_tiamat_anchor_writer import ConditionalTable

ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "deploy/aws/tiamat-staging-quarantine-successor-v3-public-2026-09-22.json"
PIN = "54865ab6738e51177c2880f1fc31baf86afb4f0f4b58bc415c943d0def39d996"
NOW = datetime(2026, 9, 22, 15, tzinfo=UTC)


def _installer() -> ModuleType:
    path = ROOT / "deploy/aws/install_tiamat_continued_quarantine_successor_v1.py"
    spec = importlib.util.spec_from_file_location("quarantine_successor_installer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verified():  # type: ignore[no-untyped-def]
    return verify_continued_quarantine_successor_package(
        json.loads(PACKAGE.read_text(encoding="utf-8")),
        now=NOW,
        expected_root_public_sha256=PIN,
    )


def test_verified_successor_installs_once_and_strong_reads() -> None:
    identity, old, new, _ = _verified()
    store = Mock()
    store.read.side_effect = [old, new]
    installer = _installer()
    status = installer.install_verified_successor(
        store,
        predecessor_sha256=old.exact_sha256,
        successor_sha256=new.exact_sha256,
        key=identity.key,
        successor=new,
        now=NOW,
    )
    assert status == "installed_and_verified"
    store.install.assert_called_once_with(new, expected_transition_sha256=old.exact_sha256, now=NOW)
    assert store.read.call_count == 2


def test_mismatched_predecessor_never_writes() -> None:
    identity, old, new, _ = _verified()
    store = Mock()
    store.read.return_value = new
    with pytest.raises(RecoveryAnchorRejected, match="compare_failed"):
        _installer().install_verified_successor(
            store,
            predecessor_sha256=old.exact_sha256,
            successor_sha256=new.exact_sha256,
            key=identity.key,
            successor=new,
            now=NOW,
        )
    store.install.assert_not_called()


def test_ambiguous_write_is_read_once_but_not_retried() -> None:
    identity, old, new, _ = _verified()
    store = Mock()
    store.read.side_effect = [old, new]
    store.install.side_effect = RecoveryAnchorRejected("recovery_anchor_unavailable")
    status = _installer().install_verified_successor(
        store,
        predecessor_sha256=old.exact_sha256,
        successor_sha256=new.exact_sha256,
        key=identity.key,
        successor=new,
        now=NOW,
    )
    assert status == "already_installed_and_verified"
    store.install.assert_called_once()
    assert store.read.call_count == 2


def test_default_preview_never_constructs_aws_client(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    installer = _installer()
    monkeypatch.setattr(
        installer,
        "dynamodb_recovery_anchor_from_environment",
        Mock(side_effect=AssertionError("AWS must not be called")),
    )
    monkeypatch.setattr(installer, "datetime", Mock(now=Mock(return_value=NOW)))
    monkeypatch.setattr(
        sys,
        "argv",
        ["installer", "--package", str(PACKAGE), "--expected-root-public-sha256", PIN],
    )
    installer.main()
    assert json.loads(capsys.readouterr().out)["status"] == "verified_not_written"


def test_execute_without_exact_digest_never_constructs_aws_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installer = _installer()
    client_factory = Mock(side_effect=AssertionError("AWS must not be called"))
    monkeypatch.setattr(installer, "dynamodb_recovery_anchor_from_environment", client_factory)
    monkeypatch.setattr(installer, "datetime", Mock(now=Mock(return_value=NOW)))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "installer",
            "--package",
            str(PACKAGE),
            "--expected-root-public-sha256",
            PIN,
            "--execute",
            "--confirm-successor-sha256",
            "0" * 64,
        ],
    )
    with pytest.raises(ValueError, match="confirm-successor-sha256"):
        installer.main()
    client_factory.assert_not_called()


def test_through_the_writer_the_installer_keeps_its_exact_digest_discipline() -> None:
    identity, old, new, _ = _verified()
    store = Mock()
    store.read.side_effect = [old, new]
    write = Mock(
        return_value=AnchorWriteResult(
            outcome="installed", transition_sha256=new.exact_sha256, transition_version=3
        )
    )
    request = AnchorWriteRequest("key", new.exact_jws, new.witness.exact_jws, b"inventory")

    status = _installer().install_through_writer(
        store,
        write,
        request,
        predecessor_sha256=old.exact_sha256,
        successor_sha256=new.exact_sha256,
        key=identity.key,
    )

    assert status == "installed_and_verified"
    write.assert_called_once_with(request)
    store.install.assert_not_called()


def test_the_published_staging_successor_installs_through_the_real_writer() -> None:
    """The live v3 package, over its real v2 predecessor, with its real witness-key rotation."""

    package = json.loads(PACKAGE.read_text(encoding="utf-8"))
    identity, old, new, _ = _verified()
    anchor_key = f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"
    table = ConditionalTable()
    table.items[anchor_key] = {
        "anchor_key": {"S": anchor_key},
        "transition_sha256": {"S": old.exact_sha256},
        "transition_version": {"N": str(old.transition_version)},
        "transition_jws": {"B": old.exact_jws},
        "witness_jws": {"B": old.witness.exact_jws},
    }
    writer = AnchorWriter(
        roots={
            anchor_key: WriterRoot(
                root_key_id=str(package["root_key_id"]),
                root_public_key_b64=str(package["root_public_key_b64"]),
                root_public_key_sha256=PIN,
            )
        },
        client=table,
        table_name="tiamat-recovery-anchor",
        clock=lambda: NOW,
    )

    result = writer.write(
        AnchorWriteRequest(
            anchor_key=anchor_key,
            transition_jws=new.exact_jws,
            witness_jws=new.witness.exact_jws,
            inventory_jws=base64.b64decode(str(package["inventory_jws_b64"])),
            head_inventory_jws=base64.b64decode(str(package["predecessor_inventory_jws_b64"])),
        )
    )

    assert (result.outcome, result.transition_sha256) == ("installed", new.exact_sha256)
    assert table.puts == 1
