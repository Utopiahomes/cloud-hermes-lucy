"""Render exact PostgreSQL grants for isolated R1-4 recovery workloads."""

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


def render_recovery_roles(
    *,
    realm_slug: str,
    authority_writer_login: str,
    cost_writer_login: str,
    authority_recovery_login: str,
    cost_recovery_login: str,
) -> str:
    if _SLUG.fullmatch(realm_slug) is None:
        raise ValueError(f"invalid realm slug: {realm_slug!r}")
    logins = {
        "__LUCY_AUTHORITY_WRITER_LOGIN__": authority_writer_login,
        "__LUCY_COST_WRITER_LOGIN__": cost_writer_login,
        "__LUCY_AUTHORITY_RECOVERY_LOGIN__": authority_recovery_login,
        "__LUCY_COST_RECOVERY_LOGIN__": cost_recovery_login,
    }
    if len(set(logins.values())) != 4:
        raise ValueError("recovery LOGIN identifiers must be distinct")
    expected = {
        authority_writer_login: f"lucy_{realm_slug}_authority_writer",
        cost_writer_login: f"lucy_{realm_slug}_cost_writer",
        authority_recovery_login: f"lucy_{realm_slug}_authority_recovery",
        cost_recovery_login: f"lucy_{realm_slug}_cost_recovery",
    }
    for login, exact in expected.items():
        if _LOGIN.fullmatch(login) is None or login != exact:
            raise ValueError(f"recovery LOGIN {login!r} does not match {exact!r}")
    return _render(
        "production_recovery_roles_v1.3.sql.example",
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realm-slug", required=True)
    for name in (
        "authority-writer",
        "cost-writer",
        "authority-recovery",
        "cost-recovery",
    ):
        parser.add_argument(f"--{name}-login", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    content = render_recovery_roles(
        realm_slug=args.realm_slug,
        authority_writer_login=args.authority_writer_login,
        cost_writer_login=args.cost_writer_login,
        authority_recovery_login=args.authority_recovery_login,
        cost_recovery_login=args.cost_recovery_login,
    )
    output = args.output.resolve()
    if output.exists() and not args.overwrite:
        raise FileExistsError(f"refusing to overwrite existing output: {output}")
    if not output.parent.is_dir():
        raise FileNotFoundError("output directory does not exist")
    output.write_text(content, encoding="utf-8", newline="\n")
    print(f"rendered={output} sha256={hashlib.sha256(content.encode()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
