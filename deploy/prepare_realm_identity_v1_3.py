"""Prepare a stable content-free private-realm identity with no external effects."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from lucy.contracts.canonical import canonical_json_bytes
from lucy.realm_identity_plan import create_realm_identity_plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--realm-slug", required=True)
    parser.add_argument("--resource-namespace", required=True)
    parser.add_argument("--aws-account-id", required=True)
    parser.add_argument("--account-slug", required=True)
    parser.add_argument("--account-display-name", required=True)
    parser.add_argument("--node-slug", required=True)
    parser.add_argument("--node-display-name", required=True)
    parser.add_argument(
        "--node-kind",
        choices=("person", "organization", "project", "community", "service"),
        required=True,
    )
    parser.add_argument("--workspace-slug", default="private")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = args.output.resolve()
    if not output.parent.is_dir():
        raise ValueError("realm identity output parent must already exist")
    if output.exists():
        raise FileExistsError("realm identity output already exists")
    plan = create_realm_identity_plan(
        realm_slug=args.realm_slug,
        resource_namespace=args.resource_namespace,
        aws_account_id=args.aws_account_id,
        account_slug=args.account_slug,
        account_display_name=args.account_display_name,
        node_slug=args.node_slug,
        node_display_name=args.node_display_name,
        node_kind=args.node_kind,
        workspace_slug=args.workspace_slug,
        planned_at=datetime.now(UTC),
    )
    output.write_bytes(canonical_json_bytes(plan) + b"\n")
    print(
        f"prepared realm={plan.realm_slug} scope={plan.content_scope_id} "
        f"digest={plan.digest} status={plan.status}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
