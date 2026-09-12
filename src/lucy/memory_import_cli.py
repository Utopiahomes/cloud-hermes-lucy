"""Local-only command line workflow for private Lucy memory imports."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from uuid import UUID

from lucy.chatgpt_import import (
    ChatGPTExportInventoryV1,
    configured_sync_roots,
    inventory_chatgpt_export,
    verified_intake_path,
)
from lucy.chatgpt_manifest import build_exact_pilot_manifests
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_import_console import PilotSelectionProposalV1


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    key = args.fingerprint_key_file.read_bytes()
    repository = Path.cwd().resolve()
    output = args.output.resolve(strict=False)
    root = args.intake_root.resolve(strict=True)
    if not output.is_relative_to(root):
        raise ValueError("import output must remain inside the verified intake root")
    output.parent.mkdir(parents=True, exist_ok=True)
    sync_roots = configured_sync_roots(dict(os.environ))
    if args.command == "inventory":
        report = inventory_chatgpt_export(
            args.zip,
            intake_root=args.intake_root,
            fingerprint_key=key,
            repository_roots=(repository,),
            synchronization_roots=sync_roots,
        )
        output.write_bytes(canonical_json_bytes(report) + b"\n")
        print(
            f"Inventoried {len(report.conversations)} conversations and "
            f"{len(report.attachments)} archive attachments; network calls: 0"
        )
        return 0
    if args.command != "manifest":
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
    built = build_exact_pilot_manifests(
        args.zip,
        intake_root=root,
        fingerprint_key=key,
        reviewed_inventory=inventory,
        selection=selection,
        campaign_id=args.campaign_id,
        extractor_version=args.extractor_version,
        prompt_version=args.prompt_version,
        provider_policy_id=args.provider_policy_id,
        model_route=args.model_route,
        repository_roots=(repository,),
        synchronization_roots=sync_roots,
    )
    artifact = {
        "bundle": built.bundle,
        "bundle_digest": built.bundle.digest,
    }
    output.write_bytes(canonical_json_bytes(artifact) + b"\n")
    print(
        f"Bound {built.bundle.included_record_count} exact records and "
        f"{built.bundle.excluded_record_count} explicit exclusions; "
        "authorization state: proposed_not_authorized; network calls: 0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
