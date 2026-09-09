"""Render execute-only PostgreSQL grants for one V1.3 security realm."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_MARKER = re.compile(r"__[A-Z][A-Z0-9_]+__")
_LOGIN = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
_SLUG = re.compile(r"[a-z][a-z0-9]{0,30}\Z")


def render_realm_roles(
    *,
    realm_slug: str,
    routine_login: str,
    policy_login: str,
    workflow_login: str,
    finality_login: str,
) -> str:
    """Render four distinct realm-bound LOGIN grants without accepting secrets."""

    if _SLUG.fullmatch(realm_slug) is None:
        raise ValueError(f"invalid realm slug: {realm_slug!r}")
    logins = {
        "__LUCY_REALM_ROUTINE_LOGIN__": routine_login,
        "__LUCY_REALM_POLICY_LOGIN__": policy_login,
        "__LUCY_REALM_WORKFLOW_LOGIN__": workflow_login,
        "__LUCY_REALM_FINALITY_LOGIN__": finality_login,
    }
    if len(set(logins.values())) != len(logins):
        raise ValueError("realm service LOGIN identifiers must be distinct")
    required_prefix = f"lucy_{realm_slug}_"
    for login in logins.values():
        if _LOGIN.fullmatch(login) is None:
            raise ValueError(f"invalid PostgreSQL LOGIN identifier: {login!r}")
        if not login.startswith(required_prefix):
            raise ValueError(
                f"realm LOGIN {login!r} does not match the reviewed {realm_slug!r} namespace"
            )
    return _render(
        "production_realm_roles_v1.3.sql.example",
        {"__LUCY_REALM_SLUG__": realm_slug, **logins},
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
    parser.add_argument("--realm-slug", required=True)
    for name in ("routine", "policy", "workflow", "finality"):
        parser.add_argument(f"--{name}-login", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    content = render_realm_roles(
        realm_slug=args.realm_slug,
        routine_login=args.routine_login,
        policy_login=args.policy_login,
        workflow_login=args.workflow_login,
        finality_login=args.finality_login,
    )
    _write(args.output, content, overwrite=args.overwrite)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
