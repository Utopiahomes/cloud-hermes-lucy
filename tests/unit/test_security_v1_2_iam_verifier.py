from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parents[2]
ACCOUNT = "123456789012"


def _verifier() -> ModuleType:
    path = ROOT / "deploy" / "aws" / "verify_security_v1_2_iam.py"
    spec = importlib.util.spec_from_file_location("verify_security_v1_2_iam", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _outputs() -> dict[str, str]:
    prefix = "lucy-prod-v12"
    return {
        "EvidenceKeyArn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/evidence",
        "RetrievalReceiptKeyArn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/retrieval",
        "DeletionReceiptKeyArn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/deletion",
        "WrappedKeyTableName": f"{prefix}-wrapped-keys",
        "RetrievalReceiptTableName": f"{prefix}-retrieval-receipts",
        "DeletionReceiptTableName": f"{prefix}-deletion-receipts",
        "DeletionIntentTableName": f"{prefix}-deletion-execution-intents",
        "DeletionJournalHeadTableName": f"{prefix}-deletion-journal-head",
        "RetrievalQuotaTableName": f"{prefix}-retrieval-quotas",
        "DeletionQuotaTableName": f"{prefix}-deletion-quotas",
        "FinalityQuarantineTablePrefix": f"{prefix}-quarantine-",
        "RetrievalExecutorAliasArn": (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-retrieval:production"
        ),
        "DeletionExecutorAliasArn": (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-deletion:production"
        ),
        "RetrievalLogGroupName": "/aws/lambda/lucy-retrieval",
        "DeletionLogGroupName": "/aws/lambda/lucy-deletion",
        "AuditCloudTrailLogGroupName": "/aws/cloudtrail/lucy-prod-v12-security-audit",
        "ArchiveRoleArn": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-render-archive",
        "EvidenceCallerRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-render-evidence-caller"
        ),
        "DeletionCallerRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-render-deletion-caller"
        ),
        "FinalityVerifierRoleArn": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-finality-verifier",
        "RecoveryAdministratorRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-recovery-administrator"
        ),
        "LambdaDeployerRoleArn": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-lambda-deployer",
        "RetrievalExecutorRuntimeRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-retrieval-runtime"
        ),
        "DeletionExecutorRuntimeRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-deletion-runtime"
        ),
        "CloudTrailLogsRoleArn": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-cloudtrail-logs",
    }


def _parameters() -> dict[str, str]:
    return {
        "ResourceNamespace": "lucy-prod-v12",
        "SecurityEnvironment": "production",
        "RenderOidcProviderArn": (
            f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.render.com/tea-workspace"
        ),
        "RenderWorkspaceId": "tea-workspace",
        "RenderEnvironmentId": "evm-production",
        "RenderArchiveServiceId": "srv-archive",
        "RenderEvidenceServiceId": "srv-evidence",
        "RenderDeletionServiceId": "srv-deletion",
        "RenderFinalityServiceId": "srv-finality",
        "KeyAdministratorPrincipalArnPattern": (
            f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_LucySecurityAdministrator_*"
        ),
    }


def test_exact_role_contract_accepts_one_inline_policy_only() -> None:
    module = _verifier()
    outputs = _outputs()
    policy_name, trust, policy = module.expected_role_contracts(
        outputs, _parameters(), ACCOUNT
    )["archive"]
    arn = outputs["ArchiveRoleArn"]
    role_name = arn.split("role/", 1)[1]
    checks = module.verify_role(
        label="archive",
        expected_arn=arn,
        account=ACCOUNT,
        role={
            "Role": {
                "Arn": arn,
                "RoleName": role_name,
                "MaxSessionDuration": 3600,
                "AssumeRolePolicyDocument": trust,
            }
        },
        inline_names={"PolicyNames": [policy_name], "IsTruncated": False},
        attached={"AttachedPolicies": [], "IsTruncated": False},
        expected_policy_name=policy_name,
        actual_policy={
            "RoleName": role_name,
            "PolicyName": policy_name,
            "PolicyDocument": policy,
        },
        expected_trust=trust,
        expected_policy=policy,
    )
    assert all(check.passed for check in checks)


def test_role_contract_rejects_extra_policy_and_resource_broadening() -> None:
    module = _verifier()
    outputs = _outputs()
    policy_name, trust, policy = module.expected_role_contracts(
        outputs, _parameters(), ACCOUNT
    )["evidence_caller"]
    arn = outputs["EvidenceCallerRoleArn"]
    role_name = arn.split("role/", 1)[1]
    broadened = json.loads(json.dumps(policy))
    broadened["Statement"][0]["Resource"] = "*"
    checks = module.verify_role(
        label="evidence_caller",
        expected_arn=arn,
        account=ACCOUNT,
        role={
            "Role": {
                "Arn": arn,
                "RoleName": role_name,
                "MaxSessionDuration": 3600,
                "AssumeRolePolicyDocument": trust,
            }
        },
        inline_names={"PolicyNames": [policy_name, "extra"], "IsTruncated": False},
        attached={"AttachedPolicies": [{"PolicyArn": "example"}], "IsTruncated": False},
        expected_policy_name=policy_name,
        actual_policy={
            "RoleName": role_name,
            "PolicyName": policy_name,
            "PolicyDocument": broadened,
        },
        expected_trust=trust,
        expected_policy=policy,
    )
    failed = {check.name for check in checks if not check.passed}
    assert {
        "iam.evidence_caller.policy_inventory",
        "iam.evidence_caller.policy_document",
    } <= failed


def test_kms_policy_comparison_is_order_insensitive_but_exact() -> None:
    module = _verifier()
    expected = module.expected_kms_contracts(_outputs(), _parameters(), ACCOUNT)["evidence"]
    reordered = {"Statement": list(reversed(expected["Statement"])), "Version": "2012-10-17"}
    assert module.verify_kms_policy(
        label="evidence", raw=json.dumps(reordered), expected=expected
    )[0].passed

    broadened = json.loads(json.dumps(expected))
    broadened["Statement"][1]["Action"] = "kms:*"
    assert not module.verify_kms_policy(
        label="evidence", raw=json.dumps(broadened), expected=expected
    )[0].passed


def test_simulation_requires_the_expected_decision() -> None:
    module = _verifier()
    case = module.SimulationCase(
        name="sample",
        role="ArchiveRoleArn",
        action="kms:Decrypt",
        resource="arn:example",
        allowed=False,
    )
    denied = {"EvaluationResults": [{"EvalDecision": "implicitDeny"}]}
    allowed = {"EvaluationResults": [{"EvalDecision": "allowed"}]}
    assert module.verify_simulation(case, denied).passed
    assert not module.verify_simulation(case, allowed).passed


def test_runtime_contracts_keep_logging_and_data_permissions_narrow() -> None:
    module = _verifier()
    contracts = module.expected_role_contracts(_outputs(), _parameters(), ACCOUNT)
    retrieval = json.dumps(contracts["retrieval_runtime"][2])
    deletion = json.dumps(contracts["deletion_runtime"][2])
    assert ":*:*" not in retrieval + deletion
    assert "dynamodb:Scan" not in retrieval + deletion
    assert "dynamodb:DeleteItem" not in retrieval
    assert "kms:Decrypt" not in deletion
    assert _outputs()["EvidenceKeyArn"] not in deletion


def test_simulation_matrix_covers_critical_positive_and_negative_boundaries() -> None:
    module = _verifier()
    cases = module.simulation_cases(_outputs(), ACCOUNT)
    names = {case.name for case in cases}
    assert {
        "evidence_caller_own_alias",
        "evidence_caller_other_alias",
        "retrieval_decrypt",
        "retrieval_scan",
        "deletion_exact_delete",
        "deletion_decrypt",
        "finality_no_data",
        "recovery_no_kms",
        "recovery_restore_source",
        "recovery_restore_quarantine_target",
        "deployer_no_invoke",
    } <= names
    assert any(case.allowed for case in cases)
    assert any(not case.allowed for case in cases)
