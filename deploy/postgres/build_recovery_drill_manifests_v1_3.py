"""Build reviewed, content-free manifests for the synthetic R1 recovery drill."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError

from deploy.postgres.provision_recovery_drill_fixture_v1_3 import (
    RecoveryDrillFixtureManifestV1,
)
from deploy.postgres.stage_recovery_drill_events_v1_3 import (
    RecoveryDrillEventManifestV1,
)
from lucy.contracts.canonical import canonical_sha256
from lucy.realm_provisioning import RealmSecurityStampV1
from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind


class RecoveryDrillManifestError(RuntimeError):
    """A recovery-drill manifest could not be built safely."""


def build_fixture(
    stamp: RealmSecurityStampV1,
    *,
    created_at: datetime,
    new_uuid: Callable[[], UUID] = uuid4,
) -> RecoveryDrillFixtureManifestV1:
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise RecoveryDrillManifestError("fixture creation time must be timezone-aware")
    return RecoveryDrillFixtureManifestV1(
        realm_slug=stamp.realm_slug,
        owner_principal_id=new_uuid(),
        owner_membership_id=new_uuid(),
        member_principal_id=new_uuid(),
        member_membership_id=new_uuid(),
        channel_binding_id=new_uuid(),
        policy_id=new_uuid(),
        identity_issuer=f"lucy://synthetic-recovery/{stamp.realm_slug}",
        owner_subject=f"synthetic-recovery-owner-{stamp.realm_slug}",
        member_subject=f"synthetic-recovery-member-{stamp.realm_slug}",
        hostname=f"synthetic-recovery-{stamp.realm_slug}.invalid",
        provisioned_at=created_at.astimezone(UTC),
    )


def build_events(
    stamp: RealmSecurityStampV1,
    fixture: RecoveryDrillFixtureManifestV1,
    authority_binding: RecoveryStreamBindingV1,
    *,
    binding_manifest_digest: str,
    created_at: datetime,
    new_uuid: Callable[[], UUID] = uuid4,
) -> RecoveryDrillEventManifestV1:
    if (
        fixture.realm_slug != stamp.realm_slug
        or authority_binding.stream_kind is not RecoveryStreamKind.AUTHORITY
        or authority_binding.binding_manifest_digest != binding_manifest_digest
        or created_at.tzinfo is None
        or created_at.utcoffset() is None
    ):
        raise RecoveryDrillManifestError("event inputs are outside the recovery boundary")
    event_nonce = new_uuid()
    attempt_id = new_uuid()
    fixture_digest = fixture.digest_hex()
    commitment_seed = {
        "fixture_manifest_digest": fixture_digest,
        "event_nonce": str(event_nonce),
        "attempt_id": str(attempt_id),
    }

    def commitment(kind: str) -> str:
        return canonical_sha256(
            commitment_seed | {"kind": kind},
            prefix=b"LUCY-R1-SYNTHETIC-RECOVERY-COMMITMENT-V1\0",
        )

    return RecoveryDrillEventManifestV1(
        realm_slug=stamp.realm_slug,
        fixture_manifest_digest=fixture_digest,
        authority_idempotency_key=f"synthetic:recovery:authority:{event_nonce}",
        source_authority_ref=f"operator:synthetic-recovery:{event_nonce}",
        attempt_id=attempt_id,
        cost_idempotency_key=f"synthetic:recovery:cost:{event_nonce}",
        request_commitment=commitment("request"),
        session_commitment=commitment("session"),
        ip_commitment=commitment("ip"),
        requested_at=created_at.astimezone(UTC),
    )


def _object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryDrillManifestError("manifest input is unavailable or invalid") from exc
    if not isinstance(value, Mapping):
        raise RecoveryDrillManifestError("manifest input must be an object")
    return value


def _stamp(path: Path) -> RealmSecurityStampV1:
    value = _object(path)
    if set(value) != {"realm_security_stamp", "realm_security_stamp_sha256"}:
        raise RecoveryDrillManifestError("realm security stamp envelope differs")
    try:
        stamp = RealmSecurityStampV1.model_validate(value["realm_security_stamp"])
    except ValidationError as exc:
        raise RecoveryDrillManifestError("realm security stamp is invalid") from exc
    if value["realm_security_stamp_sha256"] != stamp.digest_hex():
        raise RecoveryDrillManifestError("realm security stamp digest differs")
    return stamp


def _fixture(path: Path) -> RecoveryDrillFixtureManifestV1:
    value = _object(path)
    if set(value) != {"fixture_manifest", "fixture_manifest_sha256"}:
        raise RecoveryDrillManifestError("fixture manifest envelope differs")
    try:
        fixture = RecoveryDrillFixtureManifestV1.model_validate(value["fixture_manifest"])
    except ValidationError as exc:
        raise RecoveryDrillManifestError("fixture manifest is invalid") from exc
    if value["fixture_manifest_sha256"] != fixture.digest_hex():
        raise RecoveryDrillManifestError("fixture manifest digest differs")
    return fixture


def _binding(path: Path) -> RecoveryStreamBindingV1:
    try:
        return RecoveryStreamBindingV1.model_validate(_object(path))
    except ValidationError as exc:
        raise RecoveryDrillManifestError("authority binding is invalid") from exc


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite recovery manifest: {path}")
    if not path.parent.is_dir():
        raise FileNotFoundError("recovery manifest output directory does not exist")
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fixture = subparsers.add_parser("fixture")
    fixture.add_argument("--realm-stamp", type=Path, required=True)
    fixture.add_argument("--output", type=Path, required=True)
    events = subparsers.add_parser("events")
    events.add_argument("--realm-stamp", type=Path, required=True)
    events.add_argument("--fixture", type=Path, required=True)
    events.add_argument("--authority-binding", type=Path, required=True)
    events.add_argument("--binding-manifest-digest", required=True)
    events.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    stamp = _stamp(args.realm_stamp)
    now = datetime.now(UTC)
    if args.command == "fixture":
        fixture_manifest = build_fixture(stamp, created_at=now)
        payload = {
            "fixture_manifest": fixture_manifest.model_dump(mode="json"),
            "fixture_manifest_sha256": fixture_manifest.digest_hex(),
        }
    else:
        event_manifest = build_events(
            stamp,
            _fixture(args.fixture),
            _binding(args.authority_binding),
            binding_manifest_digest=args.binding_manifest_digest,
            created_at=now,
        )
        payload = {
            "event_manifest": event_manifest.model_dump(mode="json"),
            "event_manifest_sha256": event_manifest.digest_hex(),
        }
    _write(args.output, payload)
    print(f"wrote {args.command} recovery manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
