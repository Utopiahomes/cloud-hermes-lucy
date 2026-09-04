from __future__ import annotations

import json
import re
from graphlib import TopologicalSorter
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

ROOT = Path(__file__).parents[2]
AWS_DEPLOY = ROOT / "deploy" / "aws"


def _load(name: str) -> dict[str, Any]:
    return json.loads((AWS_DEPLOY / name).read_text(encoding="utf-8"))


def test_render_trust_is_bound_to_one_workspace_environment_and_service() -> None:
    statement = _load("render-oidc-trust-policy.json.example")["Statement"][0]
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    equals = statement["Condition"]["StringEquals"]
    assert set(equals.values()) == {
        "sts.amazonaws.com",
        "workspace:${RENDER_WORKSPACE_ID}:environment:${RENDER_ENVIRONMENT_ID}:"
        "service:${RENDER_SERVICE_ID}",
    }
    assert statement["Principal"]["Federated"].endswith("oidc.render.com/${RENDER_WORKSPACE_ID}")


def _actions(name: str) -> set[str]:
    actions: set[str] = set()
    for statement in _load(name)["Statement"]:
        value = statement["Action"]
        actions.update([value] if isinstance(value, str) else value)
    return actions


def _v12_render_services() -> dict[str, dict[str, Any]]:
    render = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.2.yaml.example").read_text(
            encoding="utf-8"
        )
    )
    configured = render["projects"][0]["environments"][0]["services"]
    return {service["name"]: service for service in configured}


def _v12_render_environment() -> dict[str, Any]:
    render = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.2.yaml.example").read_text(
            encoding="utf-8"
        )
    )
    return render["projects"][0]["environments"][0]


def _environment_keys(service: dict[str, Any]) -> set[str]:
    return {item["key"] for item in service["envVars"]}


def test_execution_policies_are_capability_separated() -> None:
    assert _actions("lucy-archive-policy.json.example") == {
        "kms:GenerateDataKey",
        "dynamodb:PutItem",
        "dynamodb:GetItem",
    }
    assert _actions("lucy-evidence-policy.json.example") == {
        "kms:Decrypt",
        "dynamodb:GetItem",
    }
    assert _actions("lucy-deletion-policy.json.example") == {
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert "kms:Decrypt" not in _actions("lucy-archive-policy.json.example")
    assert not any(
        action.startswith("kms:") for action in _actions("lucy-deletion-policy.json.example")
    )


def test_kms_key_statements_separate_generation_from_decryption() -> None:
    statements = _load("kms-key-policy-statements.json.example")
    assert [statement["Action"] for statement in statements] == [
        "kms:GenerateDataKey",
        "kms:Decrypt",
    ]
    assert statements[0]["Principal"] != statements[1]["Principal"]
    assert all(
        fragment not in json.dumps(statements)
        for fragment in ("kms:*", "CreateGrant", "ScheduleKeyDeletion", "PutKeyPolicy")
    )


def test_cloudformation_keeps_master_key_administration_out_of_runtime_roles() -> None:
    template = (AWS_DEPLOY / "security-baseline-v1.1.yaml").read_text(encoding="utf-8")
    deletion_section = template.split("  DeletionRole:", 1)[1].split("  SecurityAlertTopic:", 1)[0]
    assert "kms:" not in deletion_section
    assert "dynamodb:DeleteItem" in deletion_section
    assert "DeletionProtectionEnabled: true" in template
    assert "PendingWindowInDays: 30" in template
    assert "EnableKeyRotation: true" in template
    assert "KeyAdministratorPrincipalArnPattern" in template
    assert "AWSReservedSSO_LucySecurityAdministrator_*" in template
    assert "KmsRecoveryAdministratorRole" in template
    administrator_section = template.split(
        "          - Sid: IdentityCenterHumanKeyAdministrator", 1
    )[1].split("          - Sid: ArchiveGenerateOnly", 1)[0]
    assert "kms:Decrypt" not in administrator_section
    assert "kms:GenerateDataKey" not in administrator_section


def _cloudformation_named(name: str) -> dict[str, Any]:
    class CloudFormationLoader(yaml.SafeLoader):
        pass

    def construct_tag(loader: CloudFormationLoader, suffix: str, node: Any) -> Any:
        if isinstance(node, ScalarNode):
            value = loader.construct_scalar(node)
        elif isinstance(node, SequenceNode):
            value = loader.construct_sequence(node)
        elif isinstance(node, MappingNode):
            value = loader.construct_mapping(node)
        else:
            raise TypeError("unsupported YAML node")
        return {suffix if suffix == "Ref" else f"Fn::{suffix}": value}

    CloudFormationLoader.add_multi_constructor("!", construct_tag)
    return yaml.load(
        (AWS_DEPLOY / name).read_text(encoding="utf-8"),
        Loader=CloudFormationLoader,
    )


def _cloudformation() -> dict[str, Any]:
    return _cloudformation_named("security-baseline-v1.1.yaml")


def test_cloudformation_template_is_well_formed_yaml_with_expected_boundaries() -> None:
    resources = _cloudformation()["Resources"]
    assert {
        "EvidenceKey",
        "WrappedKeyRegistry",
        "ArchiveRole",
        "ArchivePolicy",
        "EvidenceRole",
        "EvidencePolicy",
        "DeletionRole",
        "AuditTrail",
        "KeyAdministrationAlert",
        "DeletionJournalHead",
        "DeletionJournalIntents",
    } <= resources.keys()


def test_journal_tables_are_retained_protected_and_backed_up() -> None:
    resources = _cloudformation()["Resources"]
    for name in ("DeletionJournalHead", "DeletionJournalIntents"):
        resource = resources[name]
        assert resource["DeletionPolicy"] == "Retain"
        assert resource["UpdateReplacePolicy"] == "Retain"
        assert resource["Properties"]["DeletionProtectionEnabled"] is True
        assert resource["Properties"]["PointInTimeRecoverySpecification"] == {
            "PointInTimeRecoveryEnabled": True
        }
    # Wrapped-key backup resurrection would defeat crypto-shredding.
    assert resources["WrappedKeyRegistry"]["Properties"]["PointInTimeRecoverySpecification"] == {
        "PointInTimeRecoveryEnabled": False
    }


def test_cloudformation_creates_kms_principals_before_key_without_cycles() -> None:
    resources = _cloudformation()["Resources"]

    def references(value: Any) -> set[str]:
        if isinstance(value, list):
            return set().union(*(references(item) for item in value))
        if not isinstance(value, dict):
            return set()
        result: set[str] = set()
        if "Ref" in value:
            result.add(value["Ref"])
        if "Fn::GetAtt" in value:
            target = value["Fn::GetAtt"]
            result.add(target.split(".")[0] if isinstance(target, str) else target[0])
        if "Fn::Sub" in value:
            sub = value["Fn::Sub"]
            template = sub if isinstance(sub, str) else sub[0]
            overrides = set() if isinstance(sub, str) else set(sub[1])
            result.update(
                token.split(".")[0]
                for token in re.findall(r"\$\{([^}]+)\}", template)
                if token not in overrides
            )
        for child in value.values():
            result.update(references(child))
        return result & resources.keys()

    dependencies = {name: references(resource) for name, resource in resources.items()}
    for name, resource in resources.items():
        explicit = resource.get("DependsOn", [])
        dependencies[name].update([explicit] if isinstance(explicit, str) else explicit)
    order = list(TopologicalSorter(dependencies).static_order())
    for role, policy, sid, action in (
        ("ArchiveRole", "ArchivePolicy", "ArchiveGenerateOnly", "kms:GenerateDataKey"),
        ("EvidenceRole", "EvidencePolicy", "EvidenceDecryptOnly", "kms:Decrypt"),
    ):
        assert order.index(role) < order.index("EvidenceKey") < order.index(policy)
        assert "Policies" not in resources[role]["Properties"]
        assert resources[policy]["Properties"]["Roles"] == [{"Ref": role}]
        statements = resources["EvidenceKey"]["Properties"]["KeyPolicy"]["Statement"]
        statement = next(item for item in statements if item["Sid"] == sid)
        assert statement["Principal"]["AWS"] == {"Fn::GetAtt": f"{role}.Arn"}
        assert statement["Action"] == action
        policy_actions = {
            item["Action"]
            for item in resources[policy]["Properties"]["PolicyDocument"]["Statement"]
        }
        expected = {
            action,
            "dynamodb:PutItem" if role == "ArchiveRole" else "dynamodb:GetItem",
        }
        if role == "ArchiveRole":
            expected.add("dynamodb:GetItem")
        assert policy_actions == expected


def test_journal_iam_separates_head_readers_from_intent_writer() -> None:
    resources = _cloudformation()["Resources"]
    archive = json.dumps(resources["ArchivePolicy"])
    evidence = json.dumps(resources["EvidencePolicy"])
    deletion = json.dumps(resources["DeletionRole"])
    assert "DeletionJournalHead" in archive and "DeletionJournalIntents" not in archive
    assert "DeletionJournalHead" in evidence and "DeletionJournalIntents" not in evidence
    assert "DeletionJournalHead" in deletion and "DeletionJournalIntents" in deletion
    assert "dynamodb:UpdateItem" in deletion and "dynamodb:PutItem" in deletion
    assert "TransactWriteItems" in deletion
    assert not any(token in deletion for token in ("dynamodb:Scan", "dynamodb:Query", "kms:"))


def test_head_readers_can_request_only_identity_and_chain_metadata() -> None:
    resources = _cloudformation()["Resources"]
    for policy_name in ("ArchivePolicy", "EvidencePolicy"):
        statements = resources[policy_name]["Properties"]["PolicyDocument"]["Statement"]
        statement = next(
            item
            for item in statements
            if item["Action"] == "dynamodb:GetItem"
            and item["Resource"] == {"Fn::GetAtt": "DeletionJournalHead.Arn"}
        )
        assert statement["Condition"] == {
            "ForAllValues:StringEquals": {
                "dynamodb:Attributes": ["journal_id", "registry_id", "sequence", "digest"]
            }
        }


def test_cloudtrail_records_all_security_table_data_events() -> None:
    resources = _cloudformation()["Resources"]
    selectors = resources["AuditTrail"]["Properties"]["EventSelectors"]
    assert len(selectors) == 1
    assert selectors[0]["ReadWriteType"] == "All"
    assert selectors[0]["IncludeManagementEvents"] is True
    assert selectors[0]["DataResources"] == [
        {
            "Type": "AWS::DynamoDB::Table",
            "Values": [
                {"Fn::GetAtt": "WrappedKeyRegistry.Arn"},
                {"Fn::GetAtt": "DeletionJournalHead.Arn"},
                {"Fn::GetAtt": "DeletionJournalIntents.Arn"},
            ],
        }
    ]


def test_policy_render_service_keeps_no_aws_role_or_journal_access() -> None:
    render = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.1.yaml.example").read_text()
    )
    services = render["projects"][0]["environments"][0]["services"]
    policy = next(service for service in services if service["name"] == "lucy-policy")
    keys = {item["key"] for item in policy["envVars"]}
    assert "AWS_ROLE_ARN" not in keys
    assert not any("JOURNAL" in key or "DYNAMODB" in key for key in keys)


def test_render_oidc_and_journal_configuration_is_exactly_service_scoped() -> None:
    render = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.1.yaml.example").read_text()
    )
    configured = render["projects"][0]["environments"][0]["services"]
    services = {service["name"]: service for service in configured}
    journal_keys = {
        "LUCY_ARCHIVE_REGISTRY_ID",
        "LUCY_DELETION_JOURNAL_ID",
        "LUCY_AWS_DELETION_HEAD_TABLE",
        "LUCY_AWS_DELETION_INTENT_TABLE",
    }
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    }
    for name, service in services.items():
        keys = [item["key"] for item in service["envVars"]]
        assert forbidden.isdisjoint(keys)
        if name == "lucy-policy":
            assert "AWS_ROLE_ARN" not in keys
            assert journal_keys.isdisjoint(keys)
        else:
            assert keys.count("AWS_ROLE_ARN") == 1
            assert journal_keys <= set(keys)


def test_initializer_is_create_only_and_never_rewinds_head() -> None:
    script = (AWS_DEPLOY / "initialize-deletion-journal.ps1").read_text()
    assert "attribute_not_exists(journal_key)" in script
    assert "put-item" in script
    assert not any(action in script for action in ("update-item", "delete-item", "transact-write"))


def test_render_example_has_no_active_static_aws_credentials() -> None:
    active_lines = [
        line.strip()
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any(
        line.startswith(
            ("AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_WEB_IDENTITY_TOKEN_FILE=")
        )
        for line in active_lines
    )


def test_v12_cloudformation_has_two_exact_executors_and_no_function_urls() -> None:
    template = _cloudformation_named("security-baseline-v1.2.yaml")
    resources = template["Resources"]
    assert {
        "RetrievalExecutorFunction",
        "DeletionExecutorFunction",
        "RetrievalExecutorVersion",
        "DeletionExecutorVersion",
        "RetrievalExecutorAlias",
        "DeletionExecutorAlias",
        "RetrievalReceiptKey",
        "DeletionReceiptKey",
        "RetrievalReceiptLedger",
        "DeletionReceiptLedger",
        "DeletionExecutionIntents",
        "RetrievalQuotaLedger",
        "DeletionQuotaLedger",
        "FinalityVerifierRole",
    } <= resources.keys()
    assert not any(resource["Type"] == "AWS::Lambda::Url" for resource in resources.values())
    for prefix in ("Retrieval", "Deletion"):
        function = resources[f"{prefix}ExecutorFunction"]["Properties"]
        version_resource = resources[f"{prefix}ExecutorVersion"]
        version = version_resource["Properties"]
        alias = resources[f"{prefix}ExecutorAlias"]["Properties"]
        assert function["Runtime"] == "python3.12"
        assert function["Architectures"] == ["x86_64"]
        assert version_resource["DeletionPolicy"] == "Retain"
        assert version_resource["UpdateReplacePolicy"] == "Retain"
        assert version["CodeSha256"] == {"Ref": "ExecutorArtifactCodeSha256"}
        assert version["Description"] == {
            "Fn::Sub": (
                "Security Baseline v1.2 ${ExecutorArtifactCodeSha256} "
                "trust-${PolicyTrustStoreSha256}"
            )
        }
        assert alias["Name"] == "production"
        assert alias["FunctionVersion"] == {
            "Fn::GetAtt": f"{prefix}ExecutorVersion.Version"
        }
        assert "$LATEST" not in json.dumps(alias)
        assert prefix.lower() in function["Description"].lower()
    assert {
        "DeletionJournalHeadTableName",
        "DeletionJournalIntentTableName",
        "RetrievalExecutorIdentity",
        "DeletionExecutorIdentity",
        "SecurityEnvironment",
        "StorageEpoch",
        "RegistryEpoch",
        "KeyEpoch",
        "ArchiveRecordVersion",
        "FinalityQuarantineTablePrefix",
    } <= template["Outputs"].keys()


def test_v12_render_has_four_continuous_backends_and_one_finality_utility() -> None:
    services = _v12_render_services()
    assert {
        name for name, service in services.items() if service["type"] == "pserv"
    } == {"lucy-routine", "lucy-policy", "lucy-evidence", "lucy-deletion"}
    finality = services["lucy-finality-utility"]
    assert finality["type"] == "cron"
    assert finality["dockerCommand"] == "python -m lucy.finality --scheduled-sentinel"
    assert finality["schedule"] == "0 0 1 1 *"
    assert all(service["region"] == "virginia" for service in services.values())


def test_v12_render_private_services_start_in_inert_resource_id_hold() -> None:
    services = _v12_render_services()
    private_services = {
        name: service for name, service in services.items() if service["type"] == "pserv"
    }
    for service in private_services.values():
        assert service["dockerCommand"] == "python -m lucy.provisioning_hold"
        marker = next(
            item
            for item in service["envVars"]
            if item["key"] == "LUCY_RESOURCE_ID_BOOTSTRAP_HOLD"
        )
        assert marker == {
            "key": "LUCY_RESOURCE_ID_BOOTSTRAP_HOLD",
            "value": "resource-id-only",
        }


def test_v12_render_database_is_private_paid_and_migration_owned() -> None:
    environment = _v12_render_environment()
    assert environment["networking"] == {"isolation": "enabled"}
    assert environment["permissions"] == {"protection": "enabled"}
    assert environment["databases"] == [
        {
            "name": "lucy-postgres",
            "region": "virginia",
            "plan": "0.5c-1g",
            "diskSizeGB": 5,
            "storageAutoscalingEnabled": False,
            "postgresMajorVersion": "18",
            "databaseName": "lucy",
            "user": "lucy_migration",
            "connectionPool": "none",
            "ipAllowList": [],
        }
    ]


def test_v12_render_capture_is_explicitly_disabled_and_credentials_are_oidc_only() -> None:
    services = _v12_render_services()
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    }
    capture_values: list[str] = []
    for service in services.values():
        assert forbidden.isdisjoint(_environment_keys(service))
        for item in service["envVars"]:
            if item["key"] == "LUCY_TRANSCRIPT_CAPTURE_ENABLED":
                capture_values.append(item["value"])
    assert capture_values == ["false"]


def test_v12_render_aws_and_database_boundaries_are_service_exact() -> None:
    services = _v12_render_services()
    routine = _environment_keys(services["lucy-routine"])
    policy = _environment_keys(services["lucy-policy"])
    evidence = _environment_keys(services["lucy-evidence"])
    deletion = _environment_keys(services["lucy-deletion"])
    finality = _environment_keys(services["lucy-finality-utility"])

    assert {"LUCY_AWS_KMS_KEY_ARN", "LUCY_AWS_DYNAMODB_KEY_TABLE"} <= routine
    assert {
        "LUCY_ARCHIVE_REGISTRY_ID",
        "LUCY_DELETION_JOURNAL_ID",
        "LUCY_AWS_DELETION_HEAD_TABLE",
        "LUCY_AWS_DELETION_INTENT_TABLE",
    } <= routine
    assert "AWS_ROLE_ARN" in routine
    assert not any(key.startswith("AWS_") or "LUCY_AWS_" in key for key in policy)
    assert {
        "LUCY_POLICY_SIGNING_PRIVATE_KEY_B64",
        "LUCY_POLICY_KEY_ID",
        "LUCY_POLICY_ISSUER",
        "LUCY_RETRIEVAL_EXECUTOR_IDENTITY",
        "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN",
        "LUCY_RETRIEVAL_EXECUTOR_VERSION",
        "LUCY_DELETION_EXECUTOR_IDENTITY",
        "LUCY_DELETION_EXECUTOR_ALIAS_ARN",
        "LUCY_DELETION_EXECUTOR_VERSION",
    } <= policy

    assert {"AWS_REGION", "AWS_ROLE_ARN", "LUCY_AWS_RETRIEVAL_EXECUTOR_ALIAS_ARN"} <= evidence
    assert {"AWS_REGION", "AWS_ROLE_ARN", "LUCY_AWS_DELETION_EXECUTOR_ALIAS_ARN"} <= deletion
    for caller in (evidence, deletion):
        assert not any("KMS" in key or "DYNAMODB" in key or "WRAPPED_KEY" in key for key in caller)
        assert "LUCY_POLICY_SIGNING_PRIVATE_KEY_B64" not in caller

    assert {"AWS_REGION", "AWS_ROLE_ARN", "LUCY_AWS_WRAPPED_KEY_TABLE"} <= finality
    assert not any("KMS" in key or "EXECUTOR_ALIAS" in key for key in finality)
    for service in services.values():
        database = next(item for item in service["envVars"] if item["key"] == "LUCY_DATABASE_URL")
        assert database == {"key": "LUCY_DATABASE_URL", "sync": False}


def test_v12_render_callers_reach_policy_only_over_private_service_discovery() -> None:
    services = _v12_render_services()
    expected = {
        "key": "LUCY_POLICY_HOSTPORT",
        "fromService": {"type": "pserv", "name": "lucy-policy", "property": "hostport"},
    }
    for name in ("lucy-evidence", "lucy-deletion"):
        item = next(
            item
            for item in services[name]["envVars"]
            if item["key"] == "LUCY_POLICY_HOSTPORT"
        )
        assert item == expected


def test_v12_render_callers_can_invoke_only_their_qualified_alias() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    for policy_name, alias_name in (
        ("EvidenceCallerPolicy", "RetrievalExecutorAlias"),
        ("DeletionCallerPolicy", "DeletionExecutorAlias"),
    ):
        statements = resources[policy_name]["Properties"]["PolicyDocument"]["Statement"]
        assert statements == [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": {"Ref": alias_name},
            }
        ]
        assert not any(
            token in json.dumps(resources[policy_name])
            for token in ("kms:", "dynamodb:", "$LATEST", "UpdateFunction", "UpdateAlias")
        )


def test_v12_runtime_roles_have_disjoint_exact_data_and_signing_permissions() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    retrieval = json.dumps(resources["RetrievalRuntimePolicy"])
    deletion = json.dumps(resources["DeletionRuntimePolicy"])
    assert resources["RetrievalRuntimePolicy"]["Properties"]["PolicyDocument"]["Statement"][
        0
    ]["Resource"] == {"Fn::GetAtt": "RetrievalLogGroup.Arn"}
    assert resources["DeletionRuntimePolicy"]["Properties"]["PolicyDocument"]["Statement"][
        0
    ]["Resource"] == {"Fn::GetAtt": "DeletionLogGroup.Arn"}
    assert "kms:Decrypt" in retrieval and "EvidenceKey.Arn" in retrieval
    assert "kms:Sign" in retrieval and "RetrievalReceiptKey.Arn" in retrieval
    assert "DeletionReceiptKey" not in retrieval
    assert "dynamodb:GetItem" in retrieval and "WrappedKeyRegistry.Arn" in retrieval
    assert "dynamodb:DeleteItem" not in retrieval

    assert "kms:Decrypt" not in deletion and "EvidenceKey" not in deletion
    assert "kms:Sign" in deletion and "DeletionReceiptKey.Arn" in deletion
    assert "RetrievalReceiptKey" not in deletion
    assert "dynamodb:DeleteItem" in deletion and "WrappedKeyRegistry.Arn" in deletion
    assert "dynamodb:GetItem" in deletion and "DeletionReceiptLedger.Arn" in deletion
    assert not any(
        token in retrieval + deletion
        for token in (
            "dynamodb:Scan",
            "dynamodb:Query",
            "dynamodb:BatchGetItem",
            "dynamodb:CreateBackup",
            "dynamodb:ExportTableToPointInTime",
            "lambda:UpdateFunction",
            "lambda:UpdateAlias",
            "kms:GenerateDataKey",
        )
    )


def test_v12_evidence_context_is_exact_seven_field_and_environment_bound() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    statements = resources["EvidenceKey"]["Properties"]["KeyPolicy"]["Statement"]
    for sid in ("ArchiveGenerateOnly", "RetrievalExecutorDecryptOnly"):
        condition = next(item for item in statements if item["Sid"] == sid)["Condition"]
        assert condition["StringEquals"] == {
            "kms:EncryptionContext:application": "cloud-hermes-lucy",
            "kms:EncryptionContext:environment": {"Ref": "SecurityEnvironment"},
        }
        assert condition["ForAllValues:StringEquals"]["kms:EncryptionContextKeys"] == [
            "application",
            "environment",
            "evidence-id",
            "storage-epoch",
            "registry-epoch",
            "key-epoch",
            "record-version",
        ]
        assert set(condition["Null"].values()) == {"false"}


def test_v12_security_change_alert_covers_data_and_monitoring_control_planes() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    pattern = resources["SecurityAdministrationAlert"]["Properties"]["EventPattern"]
    assert set(pattern["source"]) == {
        "aws.kms",
        "aws.lambda",
        "aws.iam",
        "aws.dynamodb",
        "aws.backup",
        "aws.cloudtrail",
        "aws.logs",
        "aws.events",
        "aws.cloudwatch",
        "aws.sns",
        "aws.s3",
    }
    assert set(pattern["detail"]["eventSource"]) == {
        "kms.amazonaws.com",
        "lambda.amazonaws.com",
        "iam.amazonaws.com",
        "dynamodb.amazonaws.com",
        "backup.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "logs.amazonaws.com",
        "events.amazonaws.com",
        "monitoring.amazonaws.com",
        "sns.amazonaws.com",
        "s3.amazonaws.com",
    }
    assert {
        "StopLogging",
        "DeleteTrail",
        "DeleteLogGroup",
        "DeleteMetricFilter",
        "PutMetricAlarm",
        "DisableRule",
        "DeleteTopic",
        "DeleteBucketPolicy",
        "PutBucketVersioning",
    } <= set(pattern["detail"]["eventName"])


def test_v12_recovery_window_receipts_and_intents_are_retained() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    registry = resources["WrappedKeyRegistry"]
    assert registry["DeletionPolicy"] == registry["UpdateReplacePolicy"] == "Retain"
    assert registry["Properties"]["DeletionProtectionEnabled"] is True
    assert registry["Properties"]["PointInTimeRecoverySpecification"] == {
        "PointInTimeRecoveryEnabled": True,
        "RecoveryPeriodInDays": 30,
    }
    for name in (
        "RetrievalReceiptLedger",
        "DeletionReceiptLedger",
        "DeletionExecutionIntents",
    ):
        resource = resources[name]
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
        assert resource["Properties"]["DeletionProtectionEnabled"] is True
        assert resource["Properties"]["PointInTimeRecoverySpecification"] == {
            "PointInTimeRecoveryEnabled": True
        }
    assert "StreamSpecification" not in registry["Properties"]


def test_v12_finality_and_recovery_identities_have_no_kms_or_runtime_authority() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    finality = json.dumps(resources["FinalityVerifierPolicy"])
    recovery = json.dumps(resources["RecoveryAdministratorPolicy"])
    assert "DescribeContinuousBackups" in finality
    assert "ListRecoveryPointsByResource" in finality
    assert "ListTables" in finality and "ListTagsOfResource" in finality
    assert not any(
        token in finality
        for token in ("GetItem", "PutItem", "DeleteItem", "RestoreTable", "kms:")
    )
    assert "RestoreTableToPointInTime" in recovery
    assert "GetItem" in recovery and "PutItem" in recovery
    assert "kms:" not in recovery


def test_v12_lambda_environment_has_no_static_credential_or_capture_switch() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED",
    }
    for name in ("RetrievalExecutorFunction", "DeletionExecutorFunction"):
        variables = resources[name]["Properties"]["Environment"]["Variables"]
        assert forbidden.isdisjoint(variables)
        assert variables["LUCY_EXECUTOR_ALIAS_NAME"] == "production"
        assert "LUCY_EXECUTOR_VERSION" not in variables
        assert variables["LUCY_SECURITY_STORAGE_EPOCH"] == {"Ref": "StorageEpoch"}
        assert variables["LUCY_SECURITY_REGISTRY_EPOCH"] == {"Ref": "RegistryEpoch"}
        assert variables["LUCY_SECURITY_KEY_EPOCH"] == {"Ref": "KeyEpoch"}
        assert variables["LUCY_ARCHIVE_RECORD_VERSION"] == {"Ref": "ArchiveRecordVersion"}


def test_v12_cloudformation_dependency_graph_is_acyclic() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]

    def references(value: Any) -> set[str]:
        if isinstance(value, list):
            return set().union(*(references(item) for item in value))
        if not isinstance(value, dict):
            return set()
        result: set[str] = set()
        if "Ref" in value and isinstance(value["Ref"], str):
            result.add(value["Ref"])
        if "Fn::GetAtt" in value:
            target = value["Fn::GetAtt"]
            result.add(target.split(".")[0] if isinstance(target, str) else target[0])
        if "Fn::Sub" in value:
            sub = value["Fn::Sub"]
            template = sub if isinstance(sub, str) else sub[0]
            overrides = set() if isinstance(sub, str) else set(sub[1])
            result.update(
                token.split(".")[0]
                for token in re.findall(r"\$\{([^}]+)\}", template)
                if token not in overrides
            )
        for child in value.values():
            result.update(references(child))
        return result & resources.keys()

    dependencies = {name: references(resource) for name, resource in resources.items()}
    for name, resource in resources.items():
        explicit = resource.get("DependsOn", [])
        dependencies[name].update([explicit] if isinstance(explicit, str) else explicit)
    order = list(TopologicalSorter(dependencies).static_order())
    assert order.index("RetrievalExecutorRuntimeRole") < order.index("EvidenceKey")
    assert order.index("EvidenceKey") < order.index("RetrievalExecutorFunction")
    assert order.index("RetrievalExecutorFunction") < order.index("RetrievalExecutorVersion")
    assert order.index("RetrievalExecutorVersion") < order.index("RetrievalExecutorAlias")


def test_v12_outputs_expose_every_identity_and_control_for_deployed_verification() -> None:
    outputs = _cloudformation_named("security-baseline-v1.2.yaml")["Outputs"]
    assert {
        "ArchiveRoleArn",
        "EvidenceCallerRoleArn",
        "DeletionCallerRoleArn",
        "FinalityVerifierRoleArn",
        "RecoveryAdministratorRoleArn",
        "LambdaDeployerRoleArn",
        "RetrievalExecutorRuntimeRoleArn",
        "DeletionExecutorRuntimeRoleArn",
        "PolicyTrustStoreSha256",
        "RetrievalLogGroupName",
        "DeletionLogGroupName",
        "AuditBucketName",
        "AuditTrailName",
        "SecurityAlertTopicArn",
        "SecurityAdministrationAlertName",
        "RetrievalErrorAlarmName",
        "DeletionInvocationAlarmName",
        "RetrievalFailedAlarmName",
        "DeletionFailedAlarmName",
        "RetrievalIntegrityDeniedAlarmName",
        "DeletionIntegrityDeniedAlarmName",
        "RetrievalReceiptFailureAlarmName",
        "DeletionReceiptFailureAlarmName",
        "RetrievalThrottleAlarmName",
        "DeletionThrottleAlarmName",
        "AuditCloudTrailLogGroupName",
        "CloudTrailLogsRoleArn",
        "KmsDecryptMetricFilterName",
        "RuntimeAccessDeniedMetricFilterName",
        "RecoveryUseMetricFilterName",
        "FinalityUseMetricFilterName",
        "KmsDecryptVolumeAlarmName",
        "RuntimeAccessDeniedAlarmName",
        "RecoveryAdministratorUseAlarmName",
        "FinalityVerifierUseAlarmName",
    } <= outputs.keys()


def test_v12_content_free_executor_metrics_have_immediate_action_scoped_alarms() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    expected = {
        "RetrievalFailedAlarm": ("Failed", "evidence.retrieve"),
        "DeletionFailedAlarm": ("Failed", "evidence.delete"),
        "RetrievalIntegrityDeniedAlarm": ("IntegrityDenied", "evidence.retrieve"),
        "DeletionIntegrityDeniedAlarm": ("IntegrityDenied", "evidence.delete"),
        "RetrievalReceiptFailureAlarm": ("ReceiptFailure", "evidence.retrieve"),
        "DeletionReceiptFailureAlarm": ("ReceiptFailure", "evidence.delete"),
        "RetrievalThrottleAlarm": ("Throttled", "evidence.retrieve"),
        "DeletionThrottleAlarm": ("Throttled", "evidence.delete"),
    }
    for name, (metric, action) in expected.items():
        properties = resources[name]["Properties"]
        assert properties["Namespace"] == "CloudLucy/SecurityV1_2"
        assert properties["MetricName"] == metric
        assert properties["Dimensions"] == [{"Name": "Action", "Value": action}]
        assert properties["Period"] == 300
        assert properties["EvaluationPeriods"] == properties["Threshold"] == 1
        assert properties["TreatMissingData"] == "notBreaching"
        assert properties["AlarmActions"] == [{"Ref": "SecurityAlertTopic"}]


def test_v12_cloudtrail_metrics_cover_decrypt_denials_recovery_and_finality() -> None:
    resources = _cloudformation_named("security-baseline-v1.2.yaml")["Resources"]
    bucket_policy = resources["AuditBucketPolicy"]["Properties"]["PolicyDocument"]
    tls_deny = next(
        item for item in bucket_policy["Statement"] if item.get("Sid") == "DenyInsecureTransport"
    )
    assert tls_deny["Effect"] == "Deny"
    assert tls_deny["Action"] == "s3:*"
    assert tls_deny["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    trail = resources["AuditTrail"]
    assert set(trail["DependsOn"]) == {"AuditBucketPolicy", "CloudTrailLogsPolicy"}
    assert trail["Properties"]["CloudWatchLogsLogGroupArn"] == {
        "Fn::GetAtt": "AuditCloudTrailLogGroup.Arn"
    }
    assert trail["Properties"]["CloudWatchLogsRoleArn"] == {
        "Fn::GetAtt": "CloudTrailLogsRole.Arn"
    }
    assert resources["AuditCloudTrailLogGroup"]["Properties"]["RetentionInDays"] == 90

    delivery = resources["CloudTrailLogsPolicy"]["Properties"]["PolicyDocument"][
        "Statement"
    ]
    assert delivery == [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": {"Fn::GetAtt": "AuditCloudTrailLogGroup.Arn"},
        }
    ]

    expected_filters = {
        "KmsDecryptMetricFilter": "KmsDecryptCalls",
        "RuntimeAccessDeniedMetricFilter": "RuntimeAccessDenied",
        "RecoveryUseMetricFilter": "RecoveryAdministratorUse",
        "FinalityUseMetricFilter": "FinalityVerifierUse",
    }
    for name, metric in expected_filters.items():
        properties = resources[name]["Properties"]
        assert properties["LogGroupName"] == {"Ref": "AuditCloudTrailLogGroup"}
        transformation = properties["MetricTransformations"]
        assert transformation == [
            {
                "MetricNamespace": "CloudLucy/SecurityV1_2",
                "MetricName": metric,
                "MetricValue": "1",
                "DefaultValue": 0,
            }
        ]
        assert "transcript" not in json.dumps(properties).lower()

    expected_alarms = {
        "KmsDecryptVolumeAlarm": "KmsDecryptCalls",
        "RuntimeAccessDeniedAlarm": "RuntimeAccessDenied",
        "RecoveryAdministratorUseAlarm": "RecoveryAdministratorUse",
        "FinalityVerifierUseAlarm": "FinalityVerifierUse",
    }
    for name, metric in expected_alarms.items():
        properties = resources[name]["Properties"]
        assert properties["Namespace"] == "CloudLucy/SecurityV1_2"
        assert properties["MetricName"] == metric
        assert properties["AlarmActions"] == [{"Ref": "SecurityAlertTopic"}]
        assert properties["TreatMissingData"] == "notBreaching"
