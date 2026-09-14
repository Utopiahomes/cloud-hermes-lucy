"""Local-only command line workflow for private Lucy memory imports."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.chatgpt_import import (
    ChatGPTExportInventoryV1,
    configured_sync_roots,
    inventory_chatgpt_export,
    verified_intake_path,
)
from lucy.chatgpt_manifest import (
    AuthorizedPilotManifestV1,
    PilotManifestBundleArtifactV1,
    authorize_pilot_manifest,
    build_exact_pilot_manifests,
)
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_import_console import PilotSelectionProposalV1
from lucy.memory_pilot_runner import validate_authorized_memory_pilot


class PilotExecutionPreflightV1(BaseModel):
    """Content-free evidence that one exact pilot is ready for execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    ready_for_execution: bool = True
    campaign_id: UUID
    destination_content_scope_id: UUID
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_approval_ref: UUID
    included_record_count: int = Field(ge=1)
    excluded_record_count: int = Field(ge=0)
    maximum_model_spend_microusd: int = Field(ge=0)
    maximum_attempts: int = Field(ge=1)
    expires_at: datetime
    checked_at: datetime
    network_calls: int = 0


def _write_new_artifact(path: Path, value: object) -> None:
    """Create one immutable local artifact; never replace prior review evidence."""

    with path.open("xb") as stream:
        stream.write(canonical_json_bytes(value) + b"\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory", help="inventory a ChatGPT export locally")
    inventory.add_argument("--zip", type=Path, required=True)
    inventory.add_argument("--intake-root", type=Path, required=True)
    inventory.add_argument("--fingerprint-key-file", type=Path, required=True)
    inventory.add_argument("--output", type=Path, required=True)
    manifest = commands.add_parser(
        "manifest", help="expand a reviewed selection into exact local records"
    )
    manifest.add_argument("--zip", type=Path, required=True)
    manifest.add_argument("--intake-root", type=Path, required=True)
    manifest.add_argument("--fingerprint-key-file", type=Path, required=True)
    manifest.add_argument("--inventory", type=Path, required=True)
    manifest.add_argument("--selection", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    manifest.add_argument("--campaign-id", type=UUID, required=True)
    manifest.add_argument("--extractor-version", required=True)
    manifest.add_argument("--prompt-version", required=True)
    manifest.add_argument("--provider-policy-id", required=True)
    manifest.add_argument("--model-route", required=True)
    authorize = commands.add_parser(
        "authorize", help="record separate owner authorization for one exact pilot bundle"
    )
    authorize.add_argument("--intake-root", type=Path, required=True)
    authorize.add_argument("--manifest", type=Path, required=True)
    authorize.add_argument("--expected-bundle-digest", required=True)
    authorize.add_argument("--owner-approval-ref", type=UUID, required=True)
    authorize.add_argument("--owner-actor-id", required=True)
    authorize.add_argument("--approved-at", type=datetime.fromisoformat, required=True)
    authorize.add_argument("--confirmation", required=True)
    authorize.add_argument("--output", type=Path, required=True)
    preflight = commands.add_parser(
        "preflight", help="rebuild and verify an authorized pilot without network calls"
    )
    preflight.add_argument("--zip", type=Path, required=True)
    preflight.add_argument("--intake-root", type=Path, required=True)
    preflight.add_argument("--fingerprint-key-file", type=Path, required=True)
    preflight.add_argument("--inventory", type=Path, required=True)
    preflight.add_argument("--selection", type=Path, required=True)
    preflight.add_argument("--authorization", type=Path, required=True)
    preflight.add_argument("--expected-bundle-digest", required=True)
    preflight.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = Path.cwd().resolve()
    output = args.output.resolve(strict=False)
    root = args.intake_root.resolve(strict=True)
    if not output.is_relative_to(root):
        raise ValueError("import output must remain inside the verified intake root")
    output.parent.mkdir(parents=True, exist_ok=True)
    sync_roots = configured_sync_roots(dict(os.environ))
    if args.command == "authorize":
        manifest_path = verified_intake_path(
            args.manifest,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        artifact = PilotManifestBundleArtifactV1.model_validate_json(
            manifest_path.read_bytes()
        )
        expected_confirmation = (
            f"AUTHORIZE PRIVATE LUCY PILOT {args.expected_bundle_digest}"
        )
        if args.confirmation != expected_confirmation:
            raise PermissionError("pilot authorization confirmation is not exact")
        authorization = authorize_pilot_manifest(
            artifact,
            expected_bundle_digest=args.expected_bundle_digest,
            owner_approval_ref=args.owner_approval_ref,
            owner_actor_id=args.owner_actor_id,
            approved_at=args.approved_at,
        )
        _write_new_artifact(output, authorization)
        print(
            f"Authorized exact pilot bundle {authorization.bundle_digest}; "
            "execution performed: no; network calls: 0"
        )
        return 0

    key = args.fingerprint_key_file.read_bytes()
    if args.command == "inventory":
        report = inventory_chatgpt_export(
            args.zip,
            intake_root=args.intake_root,
            fingerprint_key=key,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        _write_new_artifact(output, report)
        print(
            f"Inventoried {len(report.conversations)} conversations and "
            f"{len(report.attachments)} archive attachments; network calls: 0"
        )
        return 0
    if args.command not in {"manifest", "preflight"}:
        raise RuntimeError("unsupported command")
    inventory_path = verified_intake_path(
        args.inventory,
        intake_root=root,
        repository_roots=(repository,),
        synchronization_roots=sync_roots,
    )
    selection_path = verified_intake_path(
        args.selection,
        intake_root=root,
        repository_roots=(repository,),
        synchronization_roots=sync_roots,
    )
    if inventory_path.stat().st_size > 50_000_000:
        raise ValueError("inventory report exceeds its local parsing limit")
    if selection_path.stat().st_size > 10_000_000:
        raise ValueError("pilot selection exceeds its local parsing limit")
    inventory = ChatGPTExportInventoryV1.model_validate_json(inventory_path.read_bytes())
    selection_document = json.loads(selection_path.read_bytes())
    if not isinstance(selection_document, dict):
        raise ValueError("pilot selection document is invalid")
    selection = PilotSelectionProposalV1.model_validate(selection_document.get("proposal"))
    if selection_document.get("proposal_digest") != selection.digest:
        raise ValueError("pilot selection digest does not match its exact proposal")
    if args.command == "preflight":
        authorization_path = verified_intake_path(
            args.authorization,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        authorization = AuthorizedPilotManifestV1.model_validate_json(
            authorization_path.read_bytes()
        )
        authorized_manifest = authorization.bundle.manifest
        campaign_id = authorization.bundle.campaign_id
        extractor_version = authorized_manifest.extractor_version
        prompt_version = authorized_manifest.prompt_version
        provider_policy_id = authorized_manifest.provider_policy_id
        model_route = authorized_manifest.model_route
    else:
        campaign_id = args.campaign_id
        extractor_version = args.extractor_version
        prompt_version = args.prompt_version
        provider_policy_id = args.provider_policy_id
        model_route = args.model_route
    built = build_exact_pilot_manifests(
        args.zip,
        intake_root=root,
        fingerprint_key=key,
        reviewed_inventory=inventory,
        selection=selection,
        campaign_id=campaign_id,
        extractor_version=extractor_version,
        prompt_version=prompt_version,
        provider_policy_id=provider_policy_id,
        model_route=model_route,
        repository_roots=(repository,),
        synchronization_roots=sync_roots,
    )
    if args.command == "preflight":
        checked_at = datetime.now(UTC)
        validate_authorized_memory_pilot(
            built,
            authorization,
            expected_bundle_digest=args.expected_bundle_digest,
            now=checked_at,
        )
        manifest = built.bundle.manifest
        preflight_report = PilotExecutionPreflightV1(
            campaign_id=built.bundle.campaign_id,
            destination_content_scope_id=built.bundle.destination_content_scope_id,
            bundle_digest=built.bundle.digest,
            owner_approval_ref=authorization.owner_approval_ref,
            included_record_count=built.bundle.included_record_count,
            excluded_record_count=built.bundle.excluded_record_count,
            maximum_model_spend_microusd=manifest.max_model_spend_microusd,
            maximum_attempts=manifest.max_attempts,
            expires_at=manifest.expires_at,
            checked_at=checked_at,
        )
        _write_new_artifact(output, preflight_report)
        print(
            f"Pilot {preflight_report.bundle_digest} is exact and ready; "
            "execution performed: no; network calls: 0"
        )
        return 0
    artifact = PilotManifestBundleArtifactV1(
        bundle=built.bundle,
        bundle_digest=built.bundle.digest,
    )
    _write_new_artifact(output, artifact)
    print(
        f"Bound {built.bundle.included_record_count} exact records and "
        f"{built.bundle.excluded_record_count} explicit exclusions; "
        "authorization state: proposed_not_authorized; network calls: 0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
