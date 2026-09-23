"""Verify that the writer version behind the ``live`` alias is exactly the reviewed one.

A malformed request cannot show this: the handler validates a request before it loads its roots.
This reads the version's own pinned configuration instead, as the Lambda API returns it for the
alias, and compares it with the reviewed artifact manifest and the reviewed roots file:

    aws lambda get-function-configuration --function-name <writer> --qualifier live \
        > live-configuration.json

It checks that the alias resolves to a published version, not ``$LATEST``, of the writer function
itself; that the version's code digest is the manifest's and nothing else can add code (a zip
package, no layers, no file systems, exactly the writer's three environment variables); that its
roots are byte-for-byte the reviewed file and hash to its pinned digest; that its description names
both digests; that it runs as the writer role, whose name the stack fixes; and that the writer
accepts that configuration, with every root's public key matching its pin. Output is content-free
JSON. Exit status is 0 only if every check passes.

A valid request is still needed to show the version executes and assumes its role; the checklist
pairs this with an install on a disposable key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from lucy.shared_execution.anchor_writer import AnchorWriteRefused, WriterRoot
from lucy.shared_execution.anchor_writer_lambda import writer_from_environment

HANDLER = "lucy.shared_execution.anchor_writer_lambda.handler"
RUNTIME = "python3.12"
VARIABLES = {
    "TIAMAT_RECOVERY_ANCHOR_TABLE",
    "TIAMAT_ANCHOR_WRITER_ROOTS",
    "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256",
}


def writer_name(namespace: str, environment: str) -> str:
    """The function and its role share this name in tiamat-anchor-writer-v1.yaml."""

    return f"{namespace}-{environment}-tiamat-anchor-writer-v1"


def verify(
    configuration: dict[str, Any],
    *,
    manifest: dict[str, Any],
    reviewed_roots: bytes,
    table_name: str,
    function_name: str,
    role_arn: str,
) -> dict[str, Any]:
    failures: list[str] = []
    variables = (configuration.get("Environment") or {}).get("Variables") or {}
    code_sha256 = str(manifest.get("artifact_sha256_base64", ""))
    roots = str(variables.get("TIAMAT_ANCHOR_WRITER_ROOTS", ""))
    roots_sha256 = hashlib.sha256(reviewed_roots).hexdigest()
    version = str(configuration.get("Version", ""))

    if not version.isdigit():
        failures.append("alias_does_not_resolve_to_a_published_version")
    if configuration.get("FunctionName") != function_name:
        failures.append("function_differs")
    if (
        configuration.get("PackageType", "Zip") != "Zip"
        or configuration.get("Layers")
        or configuration.get("FileSystemConfigs")
    ):
        # The code digest covers the zip only; a layer or a file system could add code.
        failures.append("code_outside_the_artifact")
    if set(variables) != VARIABLES:
        # An extra variable such as AWS_LAMBDA_EXEC_WRAPPER or PYTHONPATH changes what runs.
        failures.append("environment_variables_differ")
    if not code_sha256 or configuration.get("CodeSha256") != code_sha256:
        failures.append("code_digest_differs_from_manifest")
    if configuration.get("Handler") != HANDLER or configuration.get("Runtime") != RUNTIME:
        failures.append("handler_or_runtime_differs")
    if roots.encode("utf-8") != reviewed_roots:
        failures.append("roots_differ_from_reviewed_file")
    if variables.get("TIAMAT_ANCHOR_WRITER_ROOTS_SHA256") != roots_sha256:
        failures.append("pinned_roots_digest_differs")
    if variables.get("TIAMAT_RECOVERY_ANCHOR_TABLE") != table_name:
        failures.append("table_differs")
    if configuration.get("Role") != role_arn:
        # The role the table's resource policy names as the only writer.
        failures.append("execution_role_differs")
    if configuration.get("Description") != (
        f"Tiamat anchor writer code-{code_sha256} roots-{roots_sha256}"
    ):
        failures.append("description_does_not_name_both_digests")

    anchor_keys: list[str] = []
    try:
        # What the deployed writer does when it loads: digest, shape, table and region.
        writer_from_environment({**variables, "AWS_REGION": "verification-only"}, client=object())
        # The writer checks a root's key against its pin only when a write uses it; check all now.
        for anchor_key, entry in sorted(json.loads(roots).items()):
            _ = WriterRoot(**entry).public_key
            anchor_keys.append(anchor_key)
    except (AnchorWriteRefused, TypeError, ValueError):
        failures.append("writer_refuses_this_configuration")

    return {
        "verified": not failures,
        "failures": failures,
        "version": version,
        "code_sha256": configuration.get("CodeSha256"),
        "roots_sha256": roots_sha256,
        "anchor_keys": anchor_keys,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function-configuration", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--roots-file",
        type=Path,
        required=True,
        help="the exact WriterRootsJson bytes the parameters file passed",
    )
    parser.add_argument("--table", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--partition", default="aws")
    args = parser.parse_args()
    name = writer_name(args.namespace, args.environment)

    report = verify(
        json.loads(args.function_configuration.read_text(encoding="utf-8")),
        manifest=json.loads(args.manifest.read_text(encoding="utf-8")),
        reviewed_roots=args.roots_file.read_bytes(),
        table_name=args.table,
        function_name=name,
        role_arn=f"arn:{args.partition}:iam::{args.account_id}:role/{name}",
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
