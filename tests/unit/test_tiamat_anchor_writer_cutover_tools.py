"""The cutover's writer probes and its check of the deployed version's pinned configuration."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution import anchor_writer_lambda
from lucy.shared_execution.anchor_writer_lambda import writer_from_environment
from tests.unit.test_tiamat_anchor_writer import ConditionalTable

ROOT = Path(__file__).resolve().parents[2]
FINAL_ROOTS = ROOT / "deploy/aws/tiamat-staging-anchor-writer-roots.json"
FINAL_ROOTS_SHA256 = "d641fe3b70eeca4f3973749880e99d7d18d8cccab7bb9b199665ddd38398a948"
STAGING_KEY = "ENV#staging#LEDGER#6177502f-3a93-429c-b68b-0ed726d1447f"
TABLE = "stoin-staging-tiamat-recovery-anchor-v1"
ROLE = "arn:aws:iam::429870640638:role/stoin-staging-anchor-writer-v1"
CODE = base64.b64encode(hashlib.sha256(b"artifact").digest()).decode()
NOW = datetime(2026, 9, 22, 18, tzinfo=UTC)


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy/aws" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _environment(roots: bytes) -> dict[str, str]:
    return {
        "TIAMAT_RECOVERY_ANCHOR_TABLE": TABLE,
        "AWS_REGION": "us-east-1",
        "TIAMAT_ANCHOR_WRITER_ROOTS": roots.decode("utf-8"),
        "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256": hashlib.sha256(roots).hexdigest(),
    }


def _invoke(
    monkeypatch: pytest.MonkeyPatch, roots: bytes, table: ConditionalTable, event: dict[str, Any]
) -> dict[str, Any]:
    writer = writer_from_environment(_environment(roots), client=table)
    monkeypatch.setattr(anchor_writer_lambda, "_writer", writer)
    return anchor_writer_lambda.handler(event, None)


@pytest.fixture
def prepared(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    report = _script("prepare_anchor_writer_probe").prepare(
        "staging", FINAL_ROOTS.read_bytes(), tmp_path, now=NOW
    )
    return report, tmp_path


def test_the_committed_final_roots_are_the_reviewed_bytes() -> None:
    raw = FINAL_ROOTS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FINAL_ROOTS_SHA256
    assert list(json.loads(raw)) == [STAGING_KEY]


def test_the_probes_add_two_disposable_keys_and_keep_the_final_roots(
    prepared: tuple[dict[str, Any], Path],
) -> None:
    report, directory = prepared
    merged = (directory / "writer-roots-with-probes.json").read_bytes()
    assert hashlib.sha256(merged).hexdigest() == report["writer_roots_sha256"]
    roots = json.loads(merged)
    final = json.loads(FINAL_ROOTS.read_bytes())
    assert roots[STAGING_KEY] == final[STAGING_KEY]
    probe_keys = {probe["anchor_key"] for probe in report["probes"].values()}
    assert set(roots) == {STAGING_KEY} | probe_keys and len(probe_keys) == 2
    for key in probe_keys:
        assert key.startswith("ENV#staging#LEDGER#") and key != STAGING_KEY
        assert roots[key]["root_key_id"] != final[STAGING_KEY]["root_key_id"]
    # The files hold nothing that could sign: public roots and signed events only.
    for path in directory.iterdir():
        assert b"PRIVATE" not in path.read_bytes()


def test_each_probe_installs_through_the_handler_then_retries_idempotently(
    prepared: tuple[dict[str, Any], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    report, directory = prepared
    merged = (directory / "writer-roots-with-probes.json").read_bytes()
    table = ConditionalTable()
    for name, probe in report["probes"].items():
        event = json.loads((directory / f"probe-event-{name}.json").read_text(encoding="utf-8"))
        first = _invoke(monkeypatch, merged, table, event)
        assert first == {
            "status": "installed",
            "transition_sha256": probe["expected_transition_sha256"],
            "transition_version": 1,
        }
        puts = table.puts
        assert _invoke(monkeypatch, merged, table, event)["status"] == "already_installed"
        assert table.puts == puts
    assert STAGING_KEY not in table.items


def test_after_the_probes_are_removed_the_writer_loads_and_refuses_their_keys(
    prepared: tuple[dict[str, Any], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Step 6's check: key_not_configured is only reachable once the roots have loaded."""

    _, directory = prepared
    event = json.loads((directory / "probe-event-before-boundary.json").read_text(encoding="utf-8"))
    table = ConditionalTable()
    answer = _invoke(monkeypatch, FINAL_ROOTS.read_bytes(), table, event)
    assert answer == {"status": "refused", "reason": "recovery_anchor_writer_key_not_configured"}
    assert table.puts == 0


def _configuration(roots: bytes, **changes: Any) -> dict[str, Any]:
    digest = hashlib.sha256(roots).hexdigest()
    configuration: dict[str, Any] = {
        "Version": "7",
        "CodeSha256": CODE,
        "Handler": "lucy.shared_execution.anchor_writer_lambda.handler",
        "Runtime": "python3.12",
        "Role": ROLE,
        "Description": f"Tiamat anchor writer code-{CODE} roots-{digest}",
        "Environment": {
            "Variables": {
                "TIAMAT_RECOVERY_ANCHOR_TABLE": TABLE,
                "TIAMAT_ANCHOR_WRITER_ROOTS": roots.decode("utf-8"),
                "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256": digest,
            }
        },
    }
    configuration.update(changes)
    return configuration


def _verify(configuration: dict[str, Any], roots: bytes) -> dict[str, Any]:
    result: dict[str, Any] = _script("verify_anchor_writer_version").verify(
        configuration,
        manifest={"artifact_sha256_base64": CODE},
        reviewed_roots=roots,
        table_name=TABLE,
        role_arn=ROLE,
    )
    return result


def test_the_reviewed_version_verifies() -> None:
    roots = FINAL_ROOTS.read_bytes()
    report = _verify(_configuration(roots), roots)
    assert report["verified"] is True
    assert report["anchor_keys"] == [STAGING_KEY]
    assert report["roots_sha256"] == FINAL_ROOTS_SHA256


def _other_roots() -> bytes:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    return json.dumps(
        {
            STAGING_KEY: {
                "root_key_id": "tiamat-recovery-root.staging.1",
                "root_public_key_b64": base64.b64encode(raw).decode(),
                "root_public_key_sha256": hashlib.sha256(raw).hexdigest(),
            }
        },
        separators=(",", ":"),
    ).encode()


def _bad_pin() -> bytes:
    document = json.loads(FINAL_ROOTS.read_bytes())
    document[STAGING_KEY]["root_public_key_sha256"] = "0" * 64
    return json.dumps(document, separators=(",", ":")).encode()


@pytest.mark.parametrize(
    ("case", "failure"),
    [
        ("latest", "alias_does_not_resolve_to_a_published_version"),
        ("code", "code_digest_differs_from_manifest"),
        ("role", "execution_role_differs"),
        ("respaced", "roots_differ_from_reviewed_file"),
        ("other_root", "roots_differ_from_reviewed_file"),
        ("description", "description_does_not_name_both_digests"),
        ("digest", "pinned_roots_digest_differs"),
        ("bad_pin", "writer_refuses_this_configuration"),
    ],
)
def test_a_version_that_is_not_the_reviewed_one_fails(case: str, failure: str) -> None:
    reviewed = FINAL_ROOTS.read_bytes()
    reviewed_for_check = reviewed
    if case == "latest":
        configuration = _configuration(reviewed, Version="$LATEST")
    elif case == "code":
        configuration = _configuration(reviewed, CodeSha256=base64.b64encode(b"x" * 32).decode())
    elif case == "role":
        configuration = _configuration(reviewed, Role=ROLE.replace("writer", "coordinator"))
    elif case == "respaced":
        # The same JSON document in different bytes is not the reviewed configuration.
        configuration = _configuration(json.dumps(json.loads(reviewed), indent=1).encode())
    elif case == "other_root":
        configuration = _configuration(_other_roots())
    elif case == "description":
        configuration = _configuration(reviewed, Description="Tiamat anchor writer")
    elif case == "digest":
        configuration = _configuration(reviewed)
        configuration["Environment"]["Variables"]["TIAMAT_ANCHOR_WRITER_ROOTS_SHA256"] = "0" * 64
    else:
        reviewed_for_check = _bad_pin()
        configuration = _configuration(reviewed_for_check)
    report = _verify(configuration, reviewed_for_check)
    assert report["verified"] is False
    assert failure in report["failures"]
