"""Read-only deployed PostgreSQL boundary verification for one V1.3 realm.

Run as a short-lived Render job with the same private, password-bearing inputs
used by the quarantine-first bootstrap. The verifier performs no migrations,
role changes, foundation writes, or admission changes.
"""

from __future__ import annotations

import json

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    BootstrapConfig,
    _verify,
)


def run(config: BootstrapConfig) -> dict[str, object]:
    report = _verify(config)
    return {
        "contract": "lucy.realm-cloud-boundary-verification.v1.3",
        "status": "passed",
        "migration_revision": report["migration_revision"],
        "runtime_admission": report["runtime_admission"],
        "capture_enabled": report["capture_enabled"],
        "content_scope_count": report["content_scope_count"],
        "active_actor_bindings": report["active_actor_bindings"],
        "active_executor_bindings": report["active_executor_bindings"],
        "directory_admission_acl_isolated": report["directory_admission_acl_isolated"],
        "offline_migration_schema_owner": report["offline_migration_schema_owner"],
        "function_owner_schema_create_removed": report[
            "function_owner_schema_create_removed"
        ],
        "runtime_login_count": len(report["verified_runtime_logins"]),
        "recovery_login_count": len(report["verified_recovery_logins"]),
        "direct_table_authority_denied": True,
    }


def main() -> int:
    try:
        report = run(BootstrapConfig.from_environment())
    except Exception as exc:
        # Inputs include credentials. Never echo an exception string from a
        # driver or parser; the class is sufficient for the operator log.
        print(
            json.dumps(
                {
                    "contract": "lucy.realm-cloud-boundary-verification.v1.3",
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
