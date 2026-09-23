"""Phase B's operator commands, run through their real ``main()`` in ceremony order.

Every step Phase B will run is invoked as an operator would: key generation, the bootstrap, the
first inventory, the checkpoint report, pending, its install, authorization, the beacon,
established, its install, the launcher, and the partition. The ledger is a fresh environment on
the disposable database, as the recovery login. Only the AWS transport is replaced: the Lambda
client invokes the real M4 writer handler in-process, over an in-memory conditional table.
Refusals an operator can trigger - a missing or wrong confirmation, a missing writer - are
checked on the way.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

import boto3  # type: ignore[import-untyped]
import psycopg
import pytest

from lucy.shared_execution import anchor_writer_lambda
from lucy.shared_execution.anchor_writer import AnchorWriter, WriterRoot
from tests.integration.conftest import DisposableRoles
from tests.integration.tiamat_signed_trust import ROOT_KEY_ID as RELEASE_ROOT_KEY_ID
from tests.integration.tiamat_signed_trust import SyntheticReleaseTrust
from tests.unit.test_tiamat_anchor_writer import ConditionalTable

ROOT = Path(__file__).resolve().parents[2]
TABLE = "tiamat-recovery-anchor"
WRITER = "arn:aws:lambda:us-east-1:000000000000:function:tiamat-anchor-writer:live"
ROOT_KEY_ID = "tiamat-recovery-root.cli-test.1"


class _Lambda:
    """What LambdaAnchorWriterClient calls; runs the real handler with the test's writer."""

    def __init__(self) -> None:
        self.writer: AnchorWriter | None = None
        self.invocations = 0

    def invoke(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["FunctionName"] == WRITER
        assert kwargs["InvocationType"] == "RequestResponse"
        self.invocations += 1
        anchor_writer_lambda._writer = self.writer
        answer = anchor_writer_lambda.handler(json.loads(kwargs["Payload"]), None)
        return {"Payload": io.BytesIO(json.dumps(answer).encode())}


def _script(relative: str) -> ModuleType:
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered first, as an import would: dataclasses resolve their module through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, relative: str, *args: str
) -> dict[str, Any]:
    monkeypatch.setattr(sys, "argv", [relative, *args])
    _script(relative).main()
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    result: dict[str, Any] = json.loads(lines[-1])
    return result


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_the_phase_b_commands_run_in_order_on_a_disposable_ledger(
    disposable_roles: DisposableRoles,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(relative: str, *args: str) -> dict[str, Any]:
        return _run(capsys, monkeypatch, relative, *args)

    environment = f"g2c-{uuid4().hex[:10]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert row is not None
    ledger_id = UUID(str(row[0]))
    with psycopg.connect(disposable_roles.recovery) as recovery:
        # What initialize_environment writes; it refuses a shared test database, so seed it.
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate (
                environment, storage_epoch, recovery_generation,
                coordinator_generation, dispatch_blocked, block_reason
            ) VALUES (%s, %s, 1, 1, true, 'initial_reconciliation_required')
            """,
            (environment, storage_epoch),
        )
    checkpoint = _write(
        tmp_path / "day-zero.json",
        {
            "environment": environment,
            "ledger_id": str(ledger_id),
            "storage_epoch": str(storage_epoch),
            "recovery_generation": 1,
            "release_inventory": {"state": "not_installed"},
            "release_heads": [],
            "settlement_position": [],
        },
    )
    run_phase_b_ceremony(
        run,
        monkeypatch,
        tmp_path,
        environment=environment,
        ledger_id=ledger_id,
        storage_epoch=storage_epoch,
        recovery_url=disposable_roles.recovery,
        day_zero_checkpoint=checkpoint,
    )


def run_phase_b_ceremony(
    run: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    environment: str,
    ledger_id: UUID,
    storage_epoch: UUID,
    recovery_url: str,
    day_zero_checkpoint: Path,
) -> dict[str, Any]:
    """Every Phase B command in order, on an initialized, blocked, empty ledger at generation 1.

    Only the AWS transport is replaced. Returns the final ``report``.
    """

    table, lambda_client = ConditionalTable(), _Lambda()
    monkeypatch.setattr(
        boto3,
        "client",
        lambda service, **_kwargs: table if service == "dynamodb" else lambda_client,
    )
    monkeypatch.setattr(anchor_writer_lambda, "_writer", None)
    monkeypatch.setenv("TIAMAT_RECOVERY_DATABASE_URL", recovery_url)
    monkeypatch.setenv("TIAMAT_RECOVERY_ANCHOR_TABLE", TABLE)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    ledger_args = ["--environment", environment]

    # Keys, offline, from the generators' own key builders. Their command lines refuse to write
    # private keys on Windows, where they cannot verify a private DACL; the ceremony runs them
    # on the offline Linux host, so only their protected file write is bypassed here.
    monkeypatch.syspath_prepend(str(ROOT / "deploy" / "aws"))
    keys = tmp_path / "keys"
    keys.mkdir()
    root_secret, root_public, witness_secret, _ = _script(
        "deploy/aws/generate_tiamat_recovery_identity_v1.py"
    ).generate_identities(
        root_key_id=ROOT_KEY_ID, witness_key_id="tiamat-recovery-witness.cli-bootstrap.1"
    )
    _write(keys / "root-private.json", root_secret)
    _write(keys / "witness-bootstrap-private.json", witness_secret)
    raw_root = base64.b64decode(root_public["root_public_key_b64"])
    pin = hashlib.sha256(raw_root).hexdigest()
    anchor_key = f"ENV#{environment}#LEDGER#{ledger_id}"
    lambda_client.writer = AnchorWriter(
        roots={anchor_key: WriterRoot(ROOT_KEY_ID, root_public["root_public_key_b64"], pin)},
        client=table,
        table_name=TABLE,
    )

    # Step 7.2: the quarantined bootstrap, through the writer.
    checkpoint = day_zero_checkpoint
    bootstrap = tmp_path / "bootstrap.json"
    run(
        "deploy/aws/prepare_tiamat_recovery_bootstrap_v1.py",
        "--root-private-identity", str(keys / "root-private.json"),
        "--witness-private-identity", str(keys / "witness-bootstrap-private.json"),
        "--environment", environment,
        "--ledger-id", str(ledger_id),
        "--storage-epoch", str(storage_epoch),
        "--checkpoint", str(checkpoint),
        "--output", str(bootstrap),
    )  # fmt: skip
    install_bootstrap = [
        "deploy/aws/install_tiamat_recovery_bootstrap_v1.py",
        "--package", str(bootstrap),
        "--expected-root-public-sha256", pin,
    ]  # fmt: skip
    assert run(*install_bootstrap)["status"] == "verified_not_written"
    assert lambda_client.invocations == 0
    with pytest.raises(ValueError, match="confirm-empty-bootstrap"):
        run(*install_bootstrap, "--execute", "--writer-function", WRITER)
    confirmation = f"bootstrap:{environment}:{ledger_id}"
    installed = run(
        *install_bootstrap,
        "--execute",
        "--confirm-empty-bootstrap",
        confirmation,
        "--writer-function",
        WRITER,
    )
    assert installed["status"] == "installed_and_verified" and lambda_client.invocations == 1

    # Step 7.3: the first release inventory, authenticated by the approved pin, gate blocked.
    release = SyntheticReleaseTrust(environment, f"caller-{uuid4().hex[:8]}", "g2c-realm")
    inventory = tmp_path / "release-inventory.jws"
    inventory.write_bytes(
        release.inventory_jws(
            [
                ("execution_profile", "profile-cli"),
                ("spending_grant", "partition-cli"),
            ]
        )
    )
    release_public = base64.b64encode(release.root_public_key.public_bytes_raw()).decode()
    release_pin = _write(
        tmp_path / "release-root-pin.json",
        {
            "format_version": "1",
            "environment": environment,
            "root_key_id": RELEASE_ROOT_KEY_ID,
            "root_public_key_sha256": hashlib.sha256(
                release.root_public_key.public_bytes_raw()
            ).hexdigest(),
        },
    )
    first = [
        "deploy/postgres/tiamat_reconciliation_ledger_v1.py", "first-inventory", *ledger_args,
        "--expected-ledger-id", str(ledger_id),
        "--expected-storage-epoch", str(storage_epoch),
        "--expected-recovery-generation", "1",
        "--inventory-jws-file", str(inventory),
        "--release-root-key-id", RELEASE_ROOT_KEY_ID,
        "--release-root-public-key-b64", release_public,
        "--release-root-pin", str(release_pin),
    ]  # fmt: skip
    preview = run(*first)
    assert preview["status"] == "verified_not_written"
    assert preview["release_root_pin"]["path"] == str(release_pin)
    with pytest.raises(ValueError, match="confirm-jws-sha256"):
        run(*first, "--execute", "--confirm-jws-sha256", "0" * 64)
    done = run(*first, "--execute", "--confirm-jws-sha256", preview["jws_sha256"])
    assert done["status"] == "installed_dispatch_still_blocked"

    # Step 7.4: the empty-ledger checkpoint for generation 2.
    report = run(
        "deploy/postgres/tiamat_reconciliation_ledger_v1.py", "report", *ledger_args,
        "--checkpoint-generation", "2",
    )  # fmt: skip
    assert report["dispatch_blocked"] is True and report["recovery_generation"] == 1
    reconciled_checkpoint = _write(tmp_path / "checkpoint-2.json", report["checkpoint"])

    # Step 7.5: pending, signed offline under a fresh witness key, installed through the writer.
    reconciled_secret, _ = _script(
        "deploy/aws/generate_tiamat_recovery_witness_successor_v1.py"
    ).generate_witness_identity(witness_key_id="tiamat-recovery-witness.cli-reconciled.2")
    _write(keys / "witness-reconciled-private.json", reconciled_secret)
    pending = tmp_path / "pending.json"
    run(
        "deploy/aws/prepare_tiamat_reconciliation_step_v1.py", "pending",
        "--head-package", str(bootstrap),
        "--checkpoint", str(reconciled_checkpoint),
        "--witness-private-identity", str(keys / "witness-reconciled-private.json"),
        "--root-private-identity", str(keys / "root-private.json"),
        "--expected-root-public-sha256", pin,
        "--output", str(pending),
    )  # fmt: skip
    install_pending = [
        "deploy/aws/install_tiamat_reconciliation_step_v1.py",
        "--package", str(pending),
        "--ceremony", "recovery_pending",
        "--expected-root-public-sha256", pin,
    ]  # fmt: skip
    pending_preview = run(*install_pending)
    assert pending_preview["status"] == "verified_not_written"
    assert pending_preview["recovery_generation"] == 2
    with pytest.raises(ValueError, match="writer-function"):
        run(
            *install_pending,
            "--execute",
            "--confirm-transition-sha256",
            pending_preview["transition_sha256"],
        )
    assert (
        run(
            *install_pending,
            "--execute",
            "--confirm-transition-sha256",
            pending_preview["transition_sha256"],
            "--writer-function",
            WRITER,
        )["status"]
        == "installed_and_verified"
    )

    # Step 7.6: authorization; confirmations must repeat the verified values.
    authorize = [
        "deploy/postgres/tiamat_reconciliation_ledger_v1.py", "authorize", *ledger_args,
        "--pending-package", str(pending),
        "--expected-root-public-sha256", pin,
        "--source-recovery-generation", "1",
    ]  # fmt: skip
    authorize_preview = run(*authorize)
    assert authorize_preview["target_recovery_generation"] == 2
    with pytest.raises(ValueError, match="confirm the verified target"):
        run(
            *authorize,
            "--execute",
            "--confirm-target-generation",
            "3",
            "--confirm-checkpoint-sha256",
            authorize_preview["checkpoint_sha256"],
        )
    assert (
        run("deploy/postgres/tiamat_reconciliation_ledger_v1.py", "report", *ledger_args)[
            "dispatch_blocked"
        ]
        is True
    )
    authorized = run(
        *authorize,
        "--execute",
        "--confirm-target-generation",
        "2",
        "--confirm-checkpoint-sha256",
        authorize_preview["checkpoint_sha256"],
    )
    assert authorized["status"] == "authorized_gate_open_pending_continuity"

    # Step 7.7: the beacon, established signed offline, installed through the writer.
    beacon = run("deploy/postgres/tiamat_reconciliation_ledger_v1.py", "beacon", *ledger_args)
    assert beacon["checkpoint_digest"] == authorize_preview["checkpoint_sha256"]
    established, trust = tmp_path / "established.json", tmp_path / "trust.json"
    run(
        "deploy/aws/prepare_tiamat_reconciliation_step_v1.py", "established",
        "--pending-package", str(pending),
        "--beacon", str(_write(tmp_path / "beacon.json", beacon)),
        "--trust-output", str(trust),
        "--root-private-identity", str(keys / "root-private.json"),
        "--expected-root-public-sha256", pin,
        "--output", str(established),
    )  # fmt: skip
    install_established = [
        "deploy/aws/install_tiamat_reconciliation_step_v1.py",
        "--package", str(established),
        "--ceremony", "continuity_established",
        "--expected-root-public-sha256", pin,
    ]  # fmt: skip
    established_preview = run(*install_established)
    assert (
        run(
            *install_established,
            "--execute",
            "--confirm-transition-sha256",
            established_preview["transition_sha256"],
            "--writer-function",
            WRITER,
        )["status"]
        == "installed_and_verified"
    )

    # Section 8: the launcher issues one claimant from the new trust file.
    claimant = run(
        "deploy/postgres/issue_tiamat_startup_attestation_v1.py",
        "--trust-package", str(trust),
        "--expected-ledger-id", str(ledger_id),
    )  # fmt: skip
    assert claimant["status"] == "claimant_issued"
    assert claimant["anchor_transition_version"] == 3
    assert claimant["anchor_transition_sha256"] == established_preview["transition_sha256"]

    # Step 7.8: the spending partition the inventory authorizes, blocked and empty.
    partition = [
        "deploy/postgres/tiamat_reconciliation_ledger_v1.py", "create-partition", *ledger_args,
        "--expected-ledger-id", str(ledger_id),
        "--expected-storage-epoch", str(storage_epoch),
        "--expected-recovery-generation", "2",
        "--caller-id", release.caller_id,
        "--realm", "g2c-realm",
        "--partition-id", "partition-cli",
    ]  # fmt: skip
    assert run(*partition)["status"] == "not_written"
    with pytest.raises(ValueError, match="confirm-partition-id"):
        run(*partition, "--execute", "--confirm-partition-id", "partition-other")
    assert run(*partition, "--execute", "--confirm-partition-id", "partition-cli")["status"] == (
        "created"
    )
    final = run("deploy/postgres/tiamat_reconciliation_ledger_v1.py", "report", *ledger_args)
    assert (final["dispatch_blocked"], final["recovery_generation"]) == (False, 2)
    assert final["counts"]["spending_partitions"] == 1
    assert final["anchor_floor"]["transition_version"] == 3
    assert lambda_client.invocations == 3
    return final
