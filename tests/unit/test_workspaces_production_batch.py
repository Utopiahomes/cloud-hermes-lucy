from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from deploy.render import workspaces_production_batch as batch

ISSUED = datetime(2026, 9, 14, 21, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]


def _service(name: str, suffix: str, commit: str) -> dict[str, str]:
    return {
        "service_id": f"srv-{suffix * 20}",
        "name": name,
        "expected_commit": commit,
        "rollback_deploy_id": f"dep-{suffix * 20}",
    }


def _plan(**changes: Any) -> batch.WorkspacesProductionBatchV1:
    cloud = "c" * 40
    workspaces = "d" * 40
    membership = batch.WorkspacesAuthorityMembershipV1.model_validate(
        {
            "realm_slug": "utopia",
            "membership_id": "10000000-0000-4000-8000-000000000001",
            "service_principal_id": "10000000-0000-4000-8000-000000000002",
            "service_binding_id": "10000000-0000-4000-8000-000000000003",
            "workspace_id": "10000000-0000-4000-8000-000000000004",
            "identity_issuer": "https://workspaces.internal.example",
            "identity_subject": "lucy-workspaces-private",
            "granted_at": ISSUED,
        }
    )
    private_service = batch.PrivateServiceTargetV1.model_validate(
        {
            "owner_id": "tea-" + "a" * 20,
            "environment_id": "evm-" + "b" * 20,
            "repo": "https://github.com/Utopiahomes/cloud-hermes-lucy",
        }
    )
    value: dict[str, Any] = {
        "batch_id": UUID("11111111-1111-4111-8111-111111111111"),
        "issued_at": ISSUED,
        "expires_at": ISSUED + timedelta(hours=2),
        "cloud_release_commit": cloud,
        "workspaces_release_commit": workspaces,
        "membership": membership,
        "membership_manifest_sha256": membership.digest_hex(),
        "private_service_config_sha256": private_service.digest_hex(),
        "transport_token_commitment": batch.token_commitment("t" * 40, authority=False),
        "authority_token_commitment": batch.token_commitment("a" * 40, authority=True),
        "existing_services": {
            "cloud_public": _service("lucy-public", "a", cloud),
            "cloud_routine": _service("lucy-routine", "b", cloud),
            "cloud_gateway": _service("lucy-telegram-private-stage1", "c", cloud),
            "workspaces_api": _service("utopia-studio-api", "d", workspaces),
            "workspaces_operations": _service("utopia-studio-operations", "e", workspaces),
            "workspaces_lucy": _service("utopia-studio-lucy", "f", workspaces),
        },
        "private_service": private_service,
    }
    value.update(changes)
    return batch.WorkspacesProductionBatchV1.model_validate(value)


def _evidence(stage: batch.Stage, plan: batch.WorkspacesProductionBatchV1) -> dict[str, Any]:
    values: dict[batch.Stage, dict[str, Any]] = {
        batch.Stage.PREFLIGHT: {
            "aws_verifier_passed": True,
            "render_drift_passed": True,
            "cloud_release_commit": plan.cloud_release_commit,
            "workspaces_release_commit": plan.workspaces_release_commit,
            "workspaces_transport_disabled": True,
            "affected_autodeploy_disabled": True,
        },
        batch.Stage.CONTAINED: {
            "cloud_public_suspended": True,
            "cloud_routine_suspended": True,
            "cloud_gateway_suspended": True,
            "database_sessions_drained": True,
            "admission_state": "quarantined",
            "capture_boundary_safe": True,
        },
        batch.Stage.MIGRATED: {
            "source_revision": "0057_public_conversation",
            "target_revision": batch.TARGET_SCHEMA,
            "admission_state": "quarantined",
            "capture_boundary_safe": True,
            "existing_surface_grants_verified": True,
            "workspaces_queue_grants_verified": True,
            "direct_table_access_denied": True,
            "residual_schema_create": False,
        },
        batch.Stage.MEMBERSHIP_APPLIED: {
            "membership_manifest_sha256": plan.membership_manifest_sha256,
            "applied": True,
            "admission_state": "quarantined",
        },
        batch.Stage.EXISTING_SURFACES_RESTORED: {
            "telegram_stage2_reopened": True,
            "public_lucy_reopened": True,
            "telegram_negative_controls_passed": True,
            "public_negative_controls_passed": True,
        },
        batch.Stage.PRIVATE_SERVICE_READY: {
            "service_id": "srv-" + "9" * 20,
            "deployed_commit": plan.cloud_release_commit,
            "auto_deploy_disabled": True,
            "health_passed": True,
            "readiness_passed": True,
            "capture_refusal_passed": True,
            "wrong_login_denied": True,
            "wrong_token_denied": True,
            "missing_membership_denied": True,
            "direct_table_access_denied": True,
        },
        batch.Stage.WORKER_CONNECTED: {
            "workspaces_release_commit": plan.workspaces_release_commit,
            "transport_commitment": plan.transport_token_commitment,
            "admission_preflight_passed": True,
            "denial_preserved_human_room": True,
        },
        batch.Stage.ACCEPTED: {
            "approved_knowledge_query_passed": True,
            "idempotent_task_delegation_passed": True,
            "cross_node_denied": True,
            "excluded_capability_denied": True,
            "unavailable_lucy_preserved_human_room": True,
            "capture_remained_disabled": True,
            "paid_inference_remained_disabled": True,
        },
    }
    return values[stage]


def _ledger(plan: batch.WorkspacesProductionBatchV1) -> list[batch.BatchStageReceiptV1]:
    receipts: list[batch.BatchStageReceiptV1] = []
    prior: str | None = None
    for index, stage in enumerate(batch.STAGE_ORDER):
        started = ISSUED + timedelta(minutes=index * 5)
        receipt = batch.BatchStageReceiptV1.model_validate(
            {
                "batch_digest": plan.digest_hex(),
                "stage": stage,
                "prior_receipt_sha256": prior,
                "started_at": started,
                "completed_at": started + timedelta(minutes=2),
                "evidence": _evidence(stage, plan),
            }
        )
        receipts.append(receipt)
        prior = receipt.digest_hex()
    return receipts


def test_empty_ledger_returns_preflight_without_performing_live_actions() -> None:
    plan = _plan()

    report = batch.status_report(plan, [], now=ISSUED)

    assert report["next_stage"] == "preflight"
    assert report["live_actions_performed_by_coordinator"] is False


def test_builder_derives_all_commitments_without_retaining_token_values() -> None:
    plan = _plan()
    inputs = batch.WorkspacesProductionBatchInputsV1.model_validate(
        plan.model_dump(
            mode="python",
            include={
                "batch_id",
                "issued_at",
                "expires_at",
                "cloud_release_commit",
                "workspaces_release_commit",
                "membership",
                "existing_services",
                "private_service",
            },
        )
    )

    built = batch.build_plan(
        inputs,
        transport_token="transport-token-000000000000000000000000",
        authority_token="authority-token-000000000000000000000000",
    )

    assert built.membership_manifest_sha256 == built.membership.digest_hex()
    assert built.private_service_config_sha256 == built.private_service.digest_hex()
    serialized = built.model_dump_json()
    assert "transport-token" not in serialized
    assert "authority-token" not in serialized


def test_production_image_contains_coordinator_without_installing_a_live_driver() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    source = (ROOT / "deploy/render/workspaces_production_batch.py").read_text(
        encoding="utf-8"
    )

    assert "deploy/render/workspaces_production_batch.py" in dockerfile
    assert "deploy/render/workspaces_production_batch_journal.py" in dockerfile
    assert "class BatchDriver(Protocol)" in source
    assert "class RenderClient" not in source


def test_cli_builder_requires_exact_authorization_and_writes_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan()
    included = {
        "batch_id",
        "issued_at",
        "expires_at",
        "cloud_release_commit",
        "workspaces_release_commit",
        "membership",
        "existing_services",
        "private_service",
    }
    input_path = tmp_path / "inputs.json"
    output_path = tmp_path / "plan.json"
    input_path.write_text(
        plan.model_dump_json(include=included),
        encoding="utf-8",
    )

    assert batch.main(["build", str(input_path), str(output_path)]) == 1
    assert not output_path.exists()

    transport = "transport-token-000000000000000000000000"
    authority = "authority-token-000000000000000000000000"
    monkeypatch.setenv(
        "LUCY_WORKSPACES_PRODUCTION_BATCH_BUILD_AUTHORIZATION",
        batch.BUILD_AUTHORIZATION,
    )
    monkeypatch.setenv("LUCY_WORKSPACES_TRANSPORT_TOKEN", transport)
    monkeypatch.setenv("LUCY_WORKSPACES_AUTHORITY_TOKEN", authority)

    assert batch.main(["build", str(input_path), str(output_path)]) == 0
    output = output_path.read_text(encoding="utf-8")
    assert transport not in output and authority not in output
    assert batch.main(["build", str(input_path), str(output_path)]) == 1


def test_complete_digest_chained_ledger_is_accepted() -> None:
    plan = _plan()
    receipts = _ledger(plan)

    assert batch.validate_ledger(plan, receipts, now=ISSUED + timedelta(hours=1)) is None
    assert batch.status_report(plan, receipts, now=ISSUED + timedelta(hours=1))["complete"]


def test_completed_or_contained_ledger_remains_auditable_after_window() -> None:
    plan = _plan()
    receipts = _ledger(plan)
    assert batch.status_report(
        plan, receipts, now=plan.expires_at + timedelta(days=30)
    )["complete"]

    partial = receipts[:2]
    containment = batch.BatchContainmentReceiptV1(
        batch_digest=plan.digest_hex(),
        failed_stage=batch.Stage.MIGRATED,
        prior_receipt_sha256=partial[-1].digest_hex(),
        occurred_at=ISSUED + timedelta(minutes=20),
        reason="operator_abort",
        workspaces_transport_disabled=True,
        affected_autodeploy_disabled=True,
        existing_surfaces="contained",
        admission_state="quarantined",
        capture_boundary_safe=True,
        private_service="absent",
    )
    assert batch.status_report(
        plan,
        partial,
        now=plan.expires_at + timedelta(days=30),
        containment=containment,
    )["contained"]


@pytest.mark.parametrize("index", range(len(batch.STAGE_ORDER)))
def test_every_prefix_resumes_at_exact_next_stage(index: int) -> None:
    plan = _plan()
    receipts = _ledger(plan)[:index]

    assert batch.validate_ledger(plan, receipts, now=ISSUED + timedelta(hours=1)) == (
        batch.STAGE_ORDER[index]
    )


def test_reordered_or_unlinked_receipts_fail_closed() -> None:
    plan = _plan()
    receipts = _ledger(plan)
    changed = receipts[1].model_copy(update={"stage": batch.Stage.MIGRATED})
    with pytest.raises(batch.BatchContractError, match="missing, duplicated, or reordered"):
        batch.validate_ledger(plan, [receipts[0], changed], now=ISSUED + timedelta(hours=1))

    unlinked = receipts[1].model_copy(update={"prior_receipt_sha256": "0" * 64})
    with pytest.raises(batch.BatchContractError, match="chain"):
        batch.validate_ledger(plan, [receipts[0], unlinked], now=ISSUED + timedelta(hours=1))


def test_pre_restore_failure_requires_quarantine_and_containment() -> None:
    plan = _plan()
    receipts = _ledger(plan)[:2]
    containment = batch.BatchContainmentReceiptV1(
        batch_digest=plan.digest_hex(),
        failed_stage=batch.Stage.MIGRATED,
        prior_receipt_sha256=receipts[-1].digest_hex(),
        occurred_at=ISSUED + timedelta(minutes=20),
        reason="operation_failed",
        workspaces_transport_disabled=True,
        affected_autodeploy_disabled=True,
        existing_surfaces="contained",
        admission_state="quarantined",
        capture_boundary_safe=True,
        private_service="absent",
    )

    batch.validate_containment(plan, receipts, containment)
    report = batch.status_report(
        plan, receipts, now=containment.occurred_at, containment=containment
    )
    assert report["contained"] is True
    assert report["next_stage"] is None

    unsafe = containment.model_copy(update={"admission_state": "ready"})
    with pytest.raises(batch.BatchContractError, match="contained and quarantined"):
        batch.validate_containment(plan, receipts, unsafe)


def test_post_restore_failure_requires_existing_surfaces_restored() -> None:
    plan = _plan()
    receipts = _ledger(plan)[:5]
    containment = batch.BatchContainmentReceiptV1(
        batch_digest=plan.digest_hex(),
        failed_stage=batch.Stage.PRIVATE_SERVICE_READY,
        prior_receipt_sha256=receipts[-1].digest_hex(),
        occurred_at=ISSUED + timedelta(minutes=30),
        reason="verification_failed",
        workspaces_transport_disabled=True,
        affected_autodeploy_disabled=True,
        existing_surfaces="restored",
        admission_state="ready",
        capture_boundary_safe=True,
        private_service="suspended",
    )

    batch.validate_containment(plan, receipts, containment)
    unsafe = containment.model_copy(update={"existing_surfaces": "contained"})
    with pytest.raises(batch.BatchContractError, match="keep existing surfaces restored"):
        batch.validate_containment(plan, receipts, unsafe)


def test_failure_during_restore_may_safely_return_to_contained_state() -> None:
    plan = _plan()
    receipts = _ledger(plan)[:4]
    containment = batch.BatchContainmentReceiptV1(
        batch_digest=plan.digest_hex(),
        failed_stage=batch.Stage.EXISTING_SURFACES_RESTORED,
        prior_receipt_sha256=receipts[-1].digest_hex(),
        occurred_at=ISSUED + timedelta(minutes=25),
        reason="operation_failed",
        workspaces_transport_disabled=True,
        affected_autodeploy_disabled=True,
        existing_surfaces="contained",
        admission_state="quarantined",
        capture_boundary_safe=True,
        private_service="absent",
    )

    batch.validate_containment(plan, receipts, containment)


def test_runner_executes_all_remaining_stages_and_persists_each_receipt() -> None:
    plan = _plan()
    expected = _ledger(plan)
    persisted: list[batch.BatchStageReceiptV1] = []

    class Driver:
        def execute_stage(
            self,
            _plan: batch.WorkspacesProductionBatchV1,
            stage: batch.Stage,
            prior_receipt_sha256: str | None,
        ) -> batch.BatchStageReceiptV1:
            receipt = expected[batch.STAGE_ORDER.index(stage)]
            assert receipt.prior_receipt_sha256 == prior_receipt_sha256
            return receipt

        def contain_failure(self, *_args: object) -> batch.BatchContainmentReceiptV1:
            raise AssertionError("successful run must not enter containment")

    completed, containment = batch.run_remaining_stages(
        plan,
        [],
        driver=Driver(),
        persist_receipt=persisted.append,
        persist_containment=lambda _receipt: None,
        now=ISSUED,
    )

    assert completed == expected
    assert persisted == expected
    assert containment is None


def test_runner_stops_at_failure_and_persists_terminal_containment() -> None:
    plan = _plan()
    expected = _ledger(plan)
    persisted: list[batch.BatchStageReceiptV1] = []
    contained: list[batch.BatchContainmentReceiptV1] = []

    class Driver:
        def execute_stage(
            self,
            _plan: batch.WorkspacesProductionBatchV1,
            stage: batch.Stage,
            _prior_receipt_sha256: str | None,
        ) -> batch.BatchStageReceiptV1:
            if stage == batch.Stage.MIGRATED:
                raise RuntimeError("synthetic failure")
            return expected[batch.STAGE_ORDER.index(stage)]

        def contain_failure(
            self,
            _plan: batch.WorkspacesProductionBatchV1,
            failed_stage: batch.Stage,
            prior_receipt_sha256: str | None,
            _error: Exception,
        ) -> batch.BatchContainmentReceiptV1:
            assert failed_stage == batch.Stage.MIGRATED
            return batch.BatchContainmentReceiptV1(
                batch_digest=plan.digest_hex(),
                failed_stage=failed_stage,
                prior_receipt_sha256=prior_receipt_sha256,
                occurred_at=ISSUED + timedelta(minutes=20),
                reason="operation_failed",
                workspaces_transport_disabled=True,
                affected_autodeploy_disabled=True,
                existing_surfaces="contained",
                admission_state="quarantined",
                capture_boundary_safe=True,
                private_service="absent",
            )

    completed, containment = batch.run_remaining_stages(
        plan,
        [],
        driver=Driver(),
        persist_receipt=persisted.append,
        persist_containment=contained.append,
        now=ISSUED,
    )

    assert [receipt.stage for receipt in completed] == [
        batch.Stage.PREFLIGHT,
        batch.Stage.CONTAINED,
    ]
    assert persisted == completed
    assert contained == [containment]


def test_receipt_from_another_batch_fails_closed() -> None:
    plan = _plan()
    receipt = _ledger(plan)[0].model_copy(update={"batch_digest": "0" * 64})

    with pytest.raises(batch.BatchContractError, match="different production batch"):
        batch.validate_ledger(plan, [receipt], now=ISSUED + timedelta(hours=1))


def test_expired_or_overlong_plan_is_rejected() -> None:
    plan = _plan()
    with pytest.raises(batch.BatchContractError, match="not active yet"):
        batch.validate_ledger(plan, [], now=plan.issued_at - timedelta(seconds=1))
    with pytest.raises(batch.BatchContractError, match="expired"):
        batch.validate_ledger(plan, [], now=plan.expires_at + timedelta(seconds=1))

    with pytest.raises(ValidationError, match="no longer than six hours"):
        _plan(expires_at=ISSUED + timedelta(hours=7))


def test_plan_rejects_changed_stage_or_schema_order() -> None:
    with pytest.raises(ValidationError, match="action order"):
        _plan(actions=tuple(reversed(batch.REQUIRED_ACTIONS)))
    with pytest.raises(ValidationError, match="source schema"):
        _plan(accepted_source_schemas=(batch.TARGET_SCHEMA,))


def test_plan_binds_membership_private_service_and_exact_render_slots() -> None:
    plan = _plan()
    changed_membership = plan.membership.model_copy(
        update={"identity_subject": "another-service"}
    )
    with pytest.raises(ValidationError, match="membership manifest digest"):
        _plan(membership=changed_membership)

    changed_private = plan.private_service.model_copy(update={"environment_id": "evm-" + "c" * 20})
    with pytest.raises(ValidationError, match="private service config digest"):
        _plan(private_service=changed_private)

    changed_services = plan.existing_services.model_dump(mode="python")
    changed_services["cloud_public"]["name"] = "lucy-public-wrong"
    with pytest.raises(ValidationError, match="wrong Render service"):
        _plan(existing_services=changed_services)


def test_token_commitments_are_domain_separated_and_values_never_enter_plan() -> None:
    transport = "shared-looking-token-transport-000000000000000000"
    authority = "shared-looking-token-authority-000000000000000000"
    plan = _plan(
        transport_token_commitment=batch.token_commitment(transport, authority=False),
        authority_token_commitment=batch.token_commitment(authority, authority=True),
    )

    batch.verify_token_pair(plan, transport, authority)
    serialized = plan.model_dump_json()
    assert transport not in serialized and authority not in serialized
    assert plan.transport_token_commitment != plan.authority_token_commitment


def test_wrong_or_reused_tokens_fail_closed() -> None:
    plan = _plan()
    with pytest.raises(batch.BatchContractError, match="transport token"):
        batch.verify_token_pair(plan, "x" * 40, "a" * 40)
    with pytest.raises(batch.BatchContractError, match="must differ"):
        batch.verify_token_pair(plan, "t" * 40, "t" * 40)


def test_stage_evidence_is_exact_and_bound_to_plan() -> None:
    plan = _plan()
    preflight = _ledger(plan)[0]
    wrong_commit = preflight.model_copy(
        update={
            "evidence": preflight.evidence.model_copy(
                update={"cloud_release_commit": "0" * 40}
            )
        }
    )
    with pytest.raises(batch.BatchContractError, match="commits differ"):
        batch.validate_ledger(plan, [wrong_commit], now=ISSUED + timedelta(hours=1))

    with pytest.raises(ValidationError):
        batch.BatchStageReceiptV1.model_validate(
            {
                "batch_digest": plan.digest_hex(),
                "stage": "preflight",
                "prior_receipt_sha256": None,
                "started_at": ISSUED,
                "completed_at": ISSUED,
                "evidence": _evidence(batch.Stage.PREFLIGHT, plan) | {"token": "secret"},
            }
        )


def test_migration_membership_service_and_worker_receipts_bind_exact_artifacts() -> None:
    plan = _plan()
    receipts = _ledger(plan)

    bad_membership = receipts[3].model_copy(
        update={
            "evidence": receipts[3].evidence.model_copy(
                update={"membership_manifest_sha256": "0" * 64}
            )
        }
    )
    with pytest.raises(batch.BatchContractError, match="membership receipt"):
        batch.validate_ledger(
            plan, receipts[:3] + [bad_membership], now=ISSUED + timedelta(hours=1)
        )

    bad_service = receipts[5].model_copy(
        update={
            "evidence": receipts[5].evidence.model_copy(
                update={"deployed_commit": "0" * 40}
            )
        }
    )
    with pytest.raises(batch.BatchContractError, match="wrong Cloud release"):
        batch.validate_ledger(plan, receipts[:5] + [bad_service], now=ISSUED + timedelta(hours=1))

    bad_worker = receipts[6].model_copy(
        update={
            "evidence": receipts[6].evidence.model_copy(
                update={"transport_commitment": "0" * 64}
            )
        }
    )
    with pytest.raises(batch.BatchContractError, match="wrong transport"):
        batch.validate_ledger(plan, receipts[:6] + [bad_worker], now=ISSUED + timedelta(hours=1))
