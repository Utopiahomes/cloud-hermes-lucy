"""Local-only command line workflow for private Lucy memory imports."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

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
from lucy.db import create_session_factory
from lucy.memory_import_console import PilotSelectionProposalV1
from lucy.memory_pilot_runner import validate_authorized_memory_pilot
from lucy.memory_pilot_transport import (
    MemoryPilotTransportRegistrationV1,
    prepare_memory_pilot_transport,
)
from lucy.memory_pilot_uploader import SequentialMemoryPilotUploader


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


class PilotAuthorizationRegistrationReceiptV1(BaseModel):
    """Content-free proof that PostgreSQL admitted one exact owner authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    object_type: str = Field(
        default="lucy.memory-pilot-authorization-registration.v1",
        pattern=r"^lucy\.memory-pilot-authorization-registration\.v1$",
    )
    owner_approval_ref: UUID
    campaign_id: UUID
    destination_content_scope_id: UUID
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool
    registered_at: datetime
    provider_calls: int = 0
    aws_calls: int = 0


class PilotTransportRegistrationReceiptV1(BaseModel):
    """Content-free proof that one exact transport plan was registered."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    object_type: str = Field(
        default="lucy.memory-pilot-transport-registration-receipt.v1",
        pattern=r"^lucy\.memory-pilot-transport-registration-receipt\.v1$",
    )
    campaign_id: UUID
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    batch_count: int = Field(ge=1)
    maximum_transport_bytes: int = Field(ge=1)
    expires_at: datetime
    replayed: bool
    registered_at: datetime
    provider_calls: int = 0
    aws_calls: int = 0


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
    register = commands.add_parser(
        "register",
        help="materialize one exact preflighted owner authorization in PostgreSQL",
    )
    register.add_argument("--intake-root", type=Path, required=True)
    register.add_argument("--authorization", type=Path, required=True)
    register.add_argument("--preflight", type=Path, required=True)
    register.add_argument("--expected-bundle-digest", required=True)
    register.add_argument("--confirmation", required=True)
    register.add_argument("--output", type=Path, required=True)
    transport_plan = commands.add_parser(
        "transport-plan",
        help="prepare exact content-free batch commitments without uploading plaintext",
    )
    transport_plan.add_argument("--zip", type=Path, required=True)
    transport_plan.add_argument("--intake-root", type=Path, required=True)
    transport_plan.add_argument("--fingerprint-key-file", type=Path, required=True)
    transport_plan.add_argument("--transfer-key-file", type=Path, required=True)
    transport_plan.add_argument("--capability-token-file", type=Path, required=True)
    transport_plan.add_argument("--inventory", type=Path, required=True)
    transport_plan.add_argument("--selection", type=Path, required=True)
    transport_plan.add_argument("--authorization", type=Path, required=True)
    transport_plan.add_argument("--expected-bundle-digest", required=True)
    transport_plan.add_argument("--maximum-microusd-per-attempt", type=int, required=True)
    transport_plan.add_argument("--timeout-seconds", type=int, required=True)
    transport_plan.add_argument("--expires-at", type=datetime.fromisoformat, required=True)
    transport_plan.add_argument("--output", type=Path, required=True)
    transport_register = commands.add_parser(
        "transport-register",
        help="register one exact content-free pilot transport plan in PostgreSQL",
    )
    transport_register.add_argument("--intake-root", type=Path, required=True)
    transport_register.add_argument("--registration", type=Path, required=True)
    transport_register.add_argument("--expected-bundle-digest", required=True)
    transport_register.add_argument("--confirmation", required=True)
    transport_register.add_argument("--output", type=Path, required=True)
    transport_upload = commands.add_parser(
        "transport-upload",
        help="rebuild and sequentially upload one exact authorized pilot",
    )
    transport_upload.add_argument("--zip", type=Path, required=True)
    transport_upload.add_argument("--intake-root", type=Path, required=True)
    transport_upload.add_argument("--fingerprint-key-file", type=Path, required=True)
    transport_upload.add_argument("--transfer-key-file", type=Path, required=True)
    transport_upload.add_argument("--capability-token-file", type=Path, required=True)
    transport_upload.add_argument("--inventory", type=Path, required=True)
    transport_upload.add_argument("--selection", type=Path, required=True)
    transport_upload.add_argument("--authorization", type=Path, required=True)
    transport_upload.add_argument("--registration", type=Path, required=True)
    transport_upload.add_argument("--expected-bundle-digest", required=True)
    transport_upload.add_argument("--maximum-microusd-per-attempt", type=int, required=True)
    transport_upload.add_argument("--timeout-seconds", type=int, required=True)
    transport_upload.add_argument("--upload-timeout-seconds", type=int, default=120)
    transport_upload.add_argument("--endpoint", required=True)
    transport_upload.add_argument("--review-directory", type=Path, required=True)
    transport_upload.add_argument("--confirmation", required=True)
    transport_upload.add_argument("--output", type=Path, required=True)
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

    if args.command == "register":
        authorization_path = verified_intake_path(
            args.authorization,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        preflight_path = verified_intake_path(
            args.preflight,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        authorization = AuthorizedPilotManifestV1.model_validate_json(
            authorization_path.read_bytes()
        )
        preflight_report = PilotExecutionPreflightV1.model_validate_json(
            preflight_path.read_bytes()
        )
        expected_confirmation = (
            f"REGISTER PRIVATE LUCY PILOT {args.expected_bundle_digest}"
        )
        now = datetime.now(UTC)
        if args.confirmation != expected_confirmation:
            raise PermissionError("pilot registration confirmation is not exact")
        if not (
            args.expected_bundle_digest == authorization.bundle_digest
            == preflight_report.bundle_digest
            and preflight_report.ready_for_execution
            and preflight_report.network_calls == 0
            and preflight_report.owner_approval_ref == authorization.owner_approval_ref
            and preflight_report.campaign_id == authorization.bundle.campaign_id
            and preflight_report.destination_content_scope_id
            == authorization.bundle.destination_content_scope_id
            and preflight_report.expires_at == authorization.bundle.manifest.expires_at
            and authorization.approved_at <= preflight_report.checked_at <= now
            and now < preflight_report.expires_at
            and (now - preflight_report.checked_at).total_seconds() <= 900
        ):
            raise PermissionError("pilot registration inputs are not one fresh exact approval")
        database_url = os.environ.get("LUCY_MIGRATION_DATABASE_URL", "").strip()
        if not database_url:
            raise ValueError("LUCY_MIGRATION_DATABASE_URL is required for registration")
        sessions = create_session_factory(database_url)
        with sessions.begin() as session:
            registered = session.execute(
                text(
                    "SELECT lucy.register_memory_import_pilot_authorization_v1("
                    "CAST(:authorization AS jsonb))"
                ),
                {
                    "authorization": canonical_json_bytes(authorization).decode("utf-8")
                },
            ).scalar_one()
        if registered.get("owner_approval_ref") != str(authorization.owner_approval_ref):
            raise RuntimeError("pilot registration acknowledgement changed owner approval")
        receipt = PilotAuthorizationRegistrationReceiptV1(
            owner_approval_ref=authorization.owner_approval_ref,
            campaign_id=authorization.bundle.campaign_id,
            destination_content_scope_id=authorization.bundle.destination_content_scope_id,
            bundle_digest=authorization.bundle_digest,
            replayed=bool(registered.get("replayed")),
            registered_at=now,
        )
        _write_new_artifact(output, receipt)
        print(
            f"Registered exact pilot bundle {receipt.bundle_digest}; "
            f"replayed: {str(receipt.replayed).lower()}; "
            "provider calls: 0; AWS calls: 0"
        )
        return 0

    if args.command == "transport-register":
        registration_path = verified_intake_path(
            args.registration,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        registration = MemoryPilotTransportRegistrationV1.model_validate_json(
            registration_path.read_bytes()
        )
        expected_confirmation = (
            f"REGISTER PRIVATE LUCY TRANSPORT {args.expected_bundle_digest}"
        )
        now = datetime.now(UTC)
        if args.confirmation != expected_confirmation:
            raise PermissionError("pilot transport registration confirmation is not exact")
        if (
            args.expected_bundle_digest != registration.bundle_digest
            or registration.expires_at <= now
        ):
            raise PermissionError("pilot transport registration is not current and exact")
        database_url = os.environ.get("LUCY_MIGRATION_DATABASE_URL", "").strip()
        if not database_url:
            raise ValueError("LUCY_MIGRATION_DATABASE_URL is required for registration")
        sessions = create_session_factory(database_url)
        with sessions.begin() as session:
            registered = session.execute(
                text(
                    "SELECT lucy.register_memory_pilot_transport_v1("
                    "CAST(:registration AS jsonb))"
                ),
                {"registration": canonical_json_bytes(registration).decode("utf-8")},
            ).scalar_one()
        if registered.get("campaign_id") != str(registration.campaign_id):
            raise RuntimeError("transport registration acknowledgement changed campaign")
        transport_receipt = PilotTransportRegistrationReceiptV1(
            campaign_id=registration.campaign_id,
            bundle_digest=registration.bundle_digest,
            batch_count=len(registration.batches),
            maximum_transport_bytes=registration.maximum_transport_bytes,
            expires_at=registration.expires_at,
            replayed=bool(registered.get("replayed")),
            registered_at=now,
        )
        _write_new_artifact(output, transport_receipt)
        print(
            f"Registered {transport_receipt.batch_count} exact transport batches; "
            f"replayed: {str(transport_receipt.replayed).lower()}; "
            "plaintext uploaded: no; provider calls: 0; AWS calls: 0"
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
    if args.command not in {
        "manifest",
        "preflight",
        "transport-plan",
        "transport-upload",
    }:
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
    if args.command in {"preflight", "transport-plan", "transport-upload"}:
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
    if args.command == "transport-plan":
        transfer_key_path = verified_intake_path(
            args.transfer_key_file,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        capability_path = verified_intake_path(
            args.capability_token_file,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        prepared = prepare_memory_pilot_transport(
            built,
            authorization,
            expected_bundle_digest=args.expected_bundle_digest,
            transfer_key=transfer_key_path.read_bytes(),
            capability_token=capability_path.read_bytes(),
            maximum_microusd_per_attempt=args.maximum_microusd_per_attempt,
            timeout_seconds=args.timeout_seconds,
            expires_at=args.expires_at,
            now=datetime.now(UTC),
        )
        _write_new_artifact(output, prepared.registration)
        print(
            f"Prepared {len(prepared.registration.batches)} exact transport commitments; "
            "plaintext uploaded: no; provider calls: 0; AWS calls: 0"
        )
        return 0
    if args.command == "transport-upload":
        registration_path = verified_intake_path(
            args.registration,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        registration = MemoryPilotTransportRegistrationV1.model_validate_json(
            registration_path.read_bytes()
        )
        expected_confirmation = (
            f"UPLOAD PRIVATE LUCY PILOT {args.expected_bundle_digest}"
        )
        if args.confirmation != expected_confirmation:
            raise PermissionError("pilot transport upload confirmation is not exact")
        transfer_key_path = verified_intake_path(
            args.transfer_key_file,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        capability_path = verified_intake_path(
            args.capability_token_file,
            intake_root=root,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        prepared = prepare_memory_pilot_transport(
            built,
            authorization,
            expected_bundle_digest=args.expected_bundle_digest,
            transfer_key=transfer_key_path.read_bytes(),
            capability_token=capability_path.read_bytes(),
            maximum_microusd_per_attempt=args.maximum_microusd_per_attempt,
            timeout_seconds=args.timeout_seconds,
            expires_at=registration.expires_at,
            now=datetime.now(UTC),
        )
        if prepared.registration != registration:
            raise PermissionError("rebuilt pilot transport differs from registration")
        upload_receipt = SequentialMemoryPilotUploader(endpoint=args.endpoint).upload(
            prepared,
            capability_token=capability_path.read_bytes(),
            intake_root=root,
            review_directory=args.review_directory,
            timeout_seconds=args.upload_timeout_seconds,
        )
        _write_new_artifact(output, upload_receipt)
        print(
            f"Uploaded {upload_receipt.uploaded_batch_count} exact pilot batches; "
            f"succeeded: {upload_receipt.succeeded_batch_count}; "
            f"candidate count: {upload_receipt.candidate_count}"
        )
        return 0
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
