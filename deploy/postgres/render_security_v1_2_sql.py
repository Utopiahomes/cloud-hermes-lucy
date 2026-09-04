"""Render reviewed Security Baseline v1.2 PostgreSQL deployment SQL.

The renderer accepts identifiers and immutable AWS outputs only. It never
accepts or writes database passwords, tokens, private keys, or transcript data.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_MARKER = re.compile(r"__[A-Z][A-Z0-9_]+__")
_LOGIN = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
_LAMBDA_ALIAS = re.compile(
    r"arn:aws:lambda:us-east-1:(?P<account>[0-9]{12}):"
    r"function:[A-Za-z0-9_-]{1,64}:(?![0-9]+\Z)[A-Za-z0-9_-]{1,128}\Z"
)
_KMS_KEY = re.compile(
    r"arn:aws:kms:us-east-1:(?P<account>[0-9]{12}):"
    r"key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)


def render_roles(
    *,
    routine_login: str,
    policy_login: str,
    evidence_login: str,
    deletion_login: str,
    finality_login: str,
) -> str:
    """Render direct grants for five distinct, pre-created production LOGINs."""
    logins = {
        "__LUCY_ROUTINE_LOGIN__": routine_login,
        "__LUCY_POLICY_LOGIN__": policy_login,
        "__LUCY_EVIDENCE_LOGIN__": evidence_login,
        "__LUCY_DELETION_LOGIN__": deletion_login,
        "__LUCY_FINALITY_LOGIN__": finality_login,
    }
    if len(set(logins.values())) != len(logins):
        raise ValueError("production service LOGIN identifiers must be distinct")
    for login in logins.values():
        if _LOGIN.fullmatch(login) is None:
            raise ValueError(f"invalid PostgreSQL LOGIN identifier: {login!r}")
    return _render("production_roles_v1.2.sql.example", logins)


def render_bindings(
    *,
    aws_account_id: str,
    retrieval_alias_arn: str,
    deletion_alias_arn: str,
    retrieval_receipt_key_arn: str,
    deletion_receipt_key_arn: str,
    retrieval_version: int,
    deletion_version: int,
    security_storage_epoch: int,
    security_registry_epoch: int,
    security_key_epoch: int,
) -> str:
    """Render immutable executor and epoch bindings while admission stays closed."""
    if re.fullmatch(r"[0-9]{12}", aws_account_id) is None:
        raise ValueError("AWS account ID must contain exactly 12 digits")
    alias_matches = [
        _LAMBDA_ALIAS.fullmatch(retrieval_alias_arn),
        _LAMBDA_ALIAS.fullmatch(deletion_alias_arn),
    ]
    key_matches = [
        _KMS_KEY.fullmatch(retrieval_receipt_key_arn),
        _KMS_KEY.fullmatch(deletion_receipt_key_arn),
    ]
    if any(match is None for match in alias_matches):
        raise ValueError("exact us-east-1 Lambda alias ARNs are required")
    if retrieval_alias_arn == deletion_alias_arn:
        raise ValueError("retrieval and deletion Lambda aliases must be distinct")
    if any(match is None for match in key_matches):
        raise ValueError("exact us-east-1 KMS key ARNs are required")
    if retrieval_receipt_key_arn == deletion_receipt_key_arn:
        raise ValueError("retrieval and deletion receipt keys must be distinct")
    accounts = {
        match.group("account")
        for match in [*alias_matches, *key_matches]
        if match is not None
    }
    if accounts != {aws_account_id}:
        raise ValueError("executor aliases and receipt keys must match the target AWS account")
    numbers = {
        "retrieval executor version": retrieval_version,
        "deletion executor version": deletion_version,
        "security storage epoch": security_storage_epoch,
        "security registry epoch": security_registry_epoch,
        "security key epoch": security_key_epoch,
    }
    for label, value in numbers.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{label} must be a positive integer")
    return _render(
        "configure_security_v1.2.sql.example",
        {
            "__RETRIEVAL_EXECUTOR_ALIAS_ARN__": retrieval_alias_arn,
            "__DELETION_EXECUTOR_ALIAS_ARN__": deletion_alias_arn,
            "__RETRIEVAL_RECEIPT_KEY_ARN__": retrieval_receipt_key_arn,
            "__DELETION_RECEIPT_KEY_ARN__": deletion_receipt_key_arn,
            "__RETRIEVAL_EXECUTOR_VERSION__": str(retrieval_version),
            "__DELETION_EXECUTOR_VERSION__": str(deletion_version),
            "__SECURITY_STORAGE_EPOCH__": str(security_storage_epoch),
            "__SECURITY_REGISTRY_EPOCH__": str(security_registry_epoch),
            "__SECURITY_KEY_EPOCH__": str(security_key_epoch),
        },
    )


def _render(template_name: str, replacements: Mapping[str, str]) -> str:
    template = (_ROOT / template_name).read_text(encoding="utf-8")
    rendered = template
    for marker, value in replacements.items():
        if template.count(marker) == 0:
            raise ValueError(f"reviewed SQL template is missing marker {marker}")
        rendered = rendered.replace(marker, value)
    unresolved = sorted(set(_MARKER.findall(rendered)))
    if unresolved:
        raise ValueError(f"unresolved reviewed SQL markers: {', '.join(unresolved)}")
    return rendered.rstrip() + "\n"


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _write(output: Path, content: str, *, overwrite: bool) -> None:
    if output.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing output: {output}")
    if not output.parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {output.parent}")
    output.write_text(content, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    print(f"rendered={output.resolve()} sha256={digest}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    roles = subparsers.add_parser("roles", help="render exact production LOGIN grants")
    for name in ("routine", "policy", "evidence", "deletion", "finality"):
        roles.add_argument(f"--{name}-login", required=True)
    roles.add_argument("--output", required=True, type=Path)
    roles.add_argument("--overwrite", action="store_true")

    bindings = subparsers.add_parser("bindings", help="render AWS executor bindings")
    bindings.add_argument("--aws-account-id", required=True)
    bindings.add_argument("--retrieval-alias-arn", required=True)
    bindings.add_argument("--deletion-alias-arn", required=True)
    bindings.add_argument("--retrieval-receipt-key-arn", required=True)
    bindings.add_argument("--deletion-receipt-key-arn", required=True)
    bindings.add_argument("--retrieval-version", required=True, type=_positive_int)
    bindings.add_argument("--deletion-version", required=True, type=_positive_int)
    bindings.add_argument("--security-storage-epoch", required=True, type=_positive_int)
    bindings.add_argument("--security-registry-epoch", required=True, type=_positive_int)
    bindings.add_argument("--security-key-epoch", required=True, type=_positive_int)
    bindings.add_argument("--output", required=True, type=Path)
    bindings.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "roles":
        content = render_roles(
            routine_login=args.routine_login,
            policy_login=args.policy_login,
            evidence_login=args.evidence_login,
            deletion_login=args.deletion_login,
            finality_login=args.finality_login,
        )
    else:
        content = render_bindings(
            aws_account_id=args.aws_account_id,
            retrieval_alias_arn=args.retrieval_alias_arn,
            deletion_alias_arn=args.deletion_alias_arn,
            retrieval_receipt_key_arn=args.retrieval_receipt_key_arn,
            deletion_receipt_key_arn=args.deletion_receipt_key_arn,
            retrieval_version=args.retrieval_version,
            deletion_version=args.deletion_version,
            security_storage_epoch=args.security_storage_epoch,
            security_registry_epoch=args.security_registry_epoch,
            security_key_epoch=args.security_key_epoch,
        )
    _write(args.output, content, overwrite=args.overwrite)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
