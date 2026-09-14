"""Derive the repeatable per-realm V1.3 AWS stamp from frozen V1.2.

The accepted V1.2 template is an immutable input.  Every transformation is
counted and the source digest is pinned so upstream drift fails closed instead
of silently changing the V1.3 security boundary.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

V12_SHA256 = "3acff006d2268ef03001e48caaf3e6ea4f9b510fb802aaac0337517e1b71c3df"


def _replace(text: str, old: str, new: str, *, count: int) -> str:
    actual = text.count(old)
    if actual != count:
        raise ValueError(
            f"frozen-template transformation expected {count} occurrence(s), found {actual}"
        )
    return text.replace(old, new)


def derive_v1_3(source: bytes) -> str:
    source = source.replace(b"\r\n", b"\n")
    digest = hashlib.sha256(source).hexdigest()
    if digest != V12_SHA256:
        raise ValueError(f"V1.2 template digest mismatch: {digest}")
    text = source.decode("utf-8")

    text = _replace(
        text,
        (
            "Description: Cloud Lucy Security Baseline v1.2 - execute-only "
            "Render callers and AWS executors"
        ),
        (
            "Description: Cloud Lucy Security Baseline v1.3 - isolated per-realm "
            "AWS security stamp"
        ),
        count=1,
    )
    text = _replace(
        text,
        "  ResourceNamespace:\n"
        "    Type: String\n"
        "    Default: lucy-prod-v12\n"
        '    AllowedPattern: "[a-z0-9-]{3,32}"\n',
        "  ResourceNamespace:\n"
        "    Type: String\n"
        '    AllowedPattern: "[a-z0-9-]{3,32}"\n'
        "    Description: Unique physical namespace for exactly one security realm\n"
        "  RealmSlug:\n"
        "    Type: String\n"
        '    AllowedPattern: "[a-z][a-z0-9]{0,30}"\n'
        "  TenantAccountUuid:\n"
        "    Type: String\n"
        '    AllowedPattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\n'
        "  NodeId:\n"
        "    Type: String\n"
        '    AllowedPattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\n'
        "  NodeTenureId:\n"
        "    Type: String\n"
        '    AllowedPattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\n'
        "  TenureEpoch:\n"
        "    Type: Number\n"
        "    MinValue: 1\n"
        "  SecurityRealmId:\n"
        "    Type: String\n"
        '    AllowedPattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\n'
        "  RealmWorkspaceUuid:\n"
        "    Type: String\n"
        '    AllowedPattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\n'
        "  DeploymentId:\n"
        "    Type: String\n"
        '    AllowedPattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\n'
        "  RealmBindingGeneration:\n"
        "    Type: Number\n"
        "    MinValue: 1\n"
        "  NodeAuthzEpoch:\n"
        "    Type: Number\n"
        "    MinValue: 1\n"
        "  AuthorityRecoveryJournalTableArn:\n"
        "    Type: String\n"
        '    AllowedPattern: "arn:aws:dynamodb:us-east-1:[0-9]{12}:table/[A-Za-z0-9_.-]+"\n'
        "    Description: ARN of this realm's independently deployed authority journal\n"
        "  CostRecoveryJournalTableArn:\n"
        "    Type: String\n"
        '    AllowedPattern: "arn:aws:dynamodb:us-east-1:[0-9]{12}:table/[A-Za-z0-9_.-]+"\n'
        "    Description: ARN of this realm's independently deployed cost journal\n",
        count=1,
    )
    text = _replace(
        text,
        "  RetrievalFunctionName:\n"
        "    Type: String\n"
        "    Default: lucy-evidence-executor-v12\n"
        "  DeletionFunctionName:\n"
        "    Type: String\n"
        "    Default: lucy-deletion-executor-v12\n",
        "",
        count=1,
    )

    old_context = """Condition:
              StringEquals:
                kms:EncryptionContext:application: cloud-hermes-lucy
                kms:EncryptionContext:environment: !Ref SecurityEnvironment
              "ForAllValues:StringEquals":
                kms:EncryptionContextKeys:
                  - application
                  - environment
                  - evidence-id
                  - storage-epoch
                  - registry-epoch
                  - key-epoch
                  - record-version
              "Null":
                kms:EncryptionContext:evidence-id: "false"
                kms:EncryptionContext:storage-epoch: "false"
                kms:EncryptionContext:registry-epoch: "false"
                kms:EncryptionContext:key-epoch: "false"
                kms:EncryptionContext:record-version: "false""".replace("\n", "\r\n")
    if "\r\n" not in text:
        old_context = old_context.replace("\r\n", "\n")
    new_context = """Condition:
              StringEquals:
                kms:EncryptionContext:contract_version: KmsEncryptionContextV2
                kms:EncryptionContext:tenant_account_id: !Ref TenantAccountUuid
                kms:EncryptionContext:node_id: !Ref NodeId
                kms:EncryptionContext:node_tenure_id: !Ref NodeTenureId
                kms:EncryptionContext:tenure_epoch: !Ref TenureEpoch
                kms:EncryptionContext:security_realm_id: !Ref SecurityRealmId
                kms:EncryptionContext:storage_epoch: !Ref StorageEpoch
                kms:EncryptionContext:purpose: EVIDENCE_DEK
              "ForAllValues:StringEquals":
                kms:EncryptionContextKeys:
                  - contract_version
                  - tenant_account_id
                  - node_id
                  - node_tenure_id
                  - tenure_epoch
                  - security_realm_id
                  - storage_epoch
                  - evidence_id
                  - purpose
              "Null":
                kms:EncryptionContext:evidence_id: "false""".replace("\n", "\r\n")
    if "\r\n" not in text:
        new_context = new_context.replace("\r\n", "\n")
    text = _replace(text, old_context, new_context, count=4)
    text = _replace(
        text,
        "  ArchivePolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyName: !Sub ${ResourceNamespace}-archive-only\n"
        "      Roles: [!Ref ArchiveRole]\n"
        "      PolicyDocument:\n"
        "        Version: \"2012-10-17\"\n"
        "        Statement:\n"
        "          - Effect: Allow",
        "  ArchivePolicy:\n"
        "    Type: AWS::IAM::Policy\n"
        "    Properties:\n"
        "      PolicyName: !Sub ${ResourceNamespace}-archive-only\n"
        "      Roles: [!Ref ArchiveRole]\n"
        "      PolicyDocument:\n"
        "        Version: \"2012-10-17\"\n"
        "        Statement:\n"
        "          - Effect: Allow",
        count=1,
    )
    archive_marker = "  ArchivePolicy:\n"
    archive_start = text.index(archive_marker)
    archive_end = text.index("\n  RetrievalLogGroup:", archive_start)
    archive = text[archive_start:archive_end]
    archive = _replace(
        archive,
        "            Action: dynamodb:PutItem\n"
        "            Resource: !GetAtt WrappedKeyRegistry.Arn",
        "            Action: [dynamodb:GetItem, dynamodb:PutItem]\n"
        "            Resource: !GetAtt WrappedKeyRegistry.Arn",
        count=1,
    )
    text = text[:archive_start] + archive + text[archive_end:]

    text = _replace(
        text,
        "      FunctionName: !Ref RetrievalFunctionName",
        "      FunctionName: !Sub ${ResourceNamespace}-evidence-executor-v13",
        count=1,
    )
    text = _replace(
        text,
        "      FunctionName: !Ref DeletionFunctionName",
        "      FunctionName: !Sub ${ResourceNamespace}-deletion-executor-v13",
        count=1,
    )
    text = _replace(
        text,
        "      LogGroupName: !Sub /aws/lambda/${RetrievalFunctionName}",
        "      LogGroupName: !Sub /aws/lambda/${ResourceNamespace}-evidence-executor-v13",
        count=1,
    )
    text = _replace(
        text,
        "      LogGroupName: !Sub /aws/lambda/${DeletionFunctionName}",
        "      LogGroupName: !Sub /aws/lambda/${ResourceNamespace}-deletion-executor-v13",
        count=1,
    )
    text = _replace(
        text,
        "Value: !Ref RetrievalFunctionName",
        "Value: !Ref RetrievalExecutorFunction",
        count=1,
    )
    text = _replace(
        text,
        "Value: !Ref DeletionFunctionName",
        "Value: !Ref DeletionExecutorFunction",
        count=1,
    )
    text = _replace(
        text,
        "      Handler: lucy.executors.handlers.retrieval_lambda_handler",
        "      Handler: lucy.executors.handlers_v1_3.realm_retrieval_lambda_handler",
        count=1,
    )
    text = _replace(
        text,
        "      Handler: lucy.executors.handlers.deletion_lambda_handler",
        "      Handler: lucy.executors.handlers_v1_3.realm_deletion_lambda_handler",
        count=1,
    )

    scope_environment = (
        "          LUCY_V13_TARGET_SCOPE_JSON: !Sub '"
        '{"tenant_account_id":"${TenantAccountUuid}",'
        '"node_id":"${NodeId}",'
        '"node_tenure_id":"${NodeTenureId}",'
        '"tenure_epoch":${TenureEpoch},'
        '"security_realm_id":"${SecurityRealmId}",'
        '"storage_epoch":${StorageEpoch}}\''
    )
    binding_environment = (
        "          LUCY_V13_EXECUTION_BINDING_JSON: !Sub '"
        '{"deployment_id":"${DeploymentId}",'
        '"active_realm_id":"${SecurityRealmId}",'
        '"active_storage_epoch":${StorageEpoch},'
        '"realm_binding_generation":${RealmBindingGeneration},'
        '"node_authz_epoch":${NodeAuthzEpoch}}\''
    )
    old_retrieval_environment = """          LUCY_EXECUTOR_ENVIRONMENT: !Ref SecurityEnvironment
          LUCY_SECURITY_STORAGE_EPOCH: !Ref StorageEpoch
          LUCY_SECURITY_REGISTRY_EPOCH: !Ref RegistryEpoch
          LUCY_SECURITY_KEY_EPOCH: !Ref KeyEpoch
          LUCY_ARCHIVE_RECORD_VERSION: !Ref ArchiveRecordVersion
          LUCY_EXECUTOR_IDENTITY: lucy-evidence-executor
          LUCY_EXECUTOR_ALIAS_NAME: production
          LUCY_EXPECTED_DATABASE_SESSION_USER: !Ref EvidenceDatabaseSessionUser"""
    new_retrieval_environment = "\n".join(
        (
            "          LUCY_EXECUTOR_ENVIRONMENT: !Ref SecurityEnvironment",
            scope_environment,
            binding_environment,
            "          LUCY_V13_WORKSPACE_ID: !Ref RealmWorkspaceUuid",
            "          LUCY_V13_CALLER_IDENTITY: !GetAtt EvidenceRole.Arn",
            "          LUCY_ARCHIVE_RECORD_VERSION: !Ref ArchiveRecordVersion",
            "          LUCY_EXECUTOR_IDENTITY: !Sub lucy-${RealmSlug}-evidence-executor",
            "          LUCY_EXECUTOR_ALIAS_NAME: realm-v13",
        )
    )
    text = _replace(text, old_retrieval_environment, new_retrieval_environment, count=1)

    old_deletion_environment = """          LUCY_EXECUTOR_ENVIRONMENT: !Ref SecurityEnvironment
          LUCY_SECURITY_STORAGE_EPOCH: !Ref StorageEpoch
          LUCY_SECURITY_REGISTRY_EPOCH: !Ref RegistryEpoch
          LUCY_SECURITY_KEY_EPOCH: !Ref KeyEpoch
          LUCY_ARCHIVE_RECORD_VERSION: !Ref ArchiveRecordVersion
          LUCY_EXECUTOR_IDENTITY: lucy-deletion-executor
          LUCY_EXECUTOR_ALIAS_NAME: production
          LUCY_EXPECTED_DATABASE_SESSION_USER: !Ref DeletionDatabaseSessionUser"""
    new_deletion_environment = "\n".join(
        (
            "          LUCY_EXECUTOR_ENVIRONMENT: !Ref SecurityEnvironment",
            scope_environment,
            binding_environment,
            "          LUCY_V13_WORKSPACE_ID: !Ref RealmWorkspaceUuid",
            "          LUCY_V13_CALLER_IDENTITY: !GetAtt DeletionRole.Arn",
            "          LUCY_ARCHIVE_RECORD_VERSION: !Ref ArchiveRecordVersion",
            "          LUCY_EXECUTOR_IDENTITY: !Sub lucy-${RealmSlug}-deletion-executor",
            "          LUCY_EXECUTOR_ALIAS_NAME: realm-v13",
        )
    )
    text = _replace(text, old_deletion_environment, new_deletion_environment, count=1)
    text = _replace(
        text,
        "            Action: dynamodb:DeleteItem\n"
        "            Resource: !GetAtt WrappedKeyRegistry.Arn",
        "            Action: dynamodb:UpdateItem\n"
        "            Resource: !GetAtt WrappedKeyRegistry.Arn",
        count=1,
    )
    text = _replace(
        text,
        "          LUCY_AWS_DELETION_INTENT_TABLE: !Ref DeletionExecutionIntents\n",
        "          LUCY_AWS_DELETION_INTENT_TABLE: !Ref DeletionExecutionIntents\n"
        "          LUCY_ARCHIVE_REGISTRY_ID: !Ref ArchiveRegistryId\n",
        count=1,
    )

    text = _replace(text, "      Name: production", "      Name: realm-v13", count=2)
    text = _replace(text, "CloudLucy/SecurityV1_2", "CloudLucy/SecurityV1_3", count=16)
    text = _replace(text, "Cloud Lucy v1.2", "Cloud Lucy v1.3", count=5)
    text = _replace(text, "Security Baseline v1.2", "Security Baseline v1.3", count=2)
    text = _replace(
        text,
        "                - !GetAtt DeletionJournalIntents.Arn\n"
        "            - Type: AWS::Lambda::Function",
        "                - !GetAtt DeletionJournalIntents.Arn\n"
        "                - !Ref AuthorityRecoveryJournalTableArn\n"
        "                - !Ref CostRecoveryJournalTableArn\n"
        "            - Type: AWS::Lambda::Function",
        count=1,
    )
    text = _replace(
        text,
        "  RetrievalExecutorIdentity: {Value: lucy-evidence-executor}",
        "  RetrievalExecutorIdentity: {Value: !Sub 'lucy-${RealmSlug}-evidence-executor'}",
        count=1,
    )
    text = _replace(
        text,
        "  DeletionExecutorIdentity: {Value: lucy-deletion-executor}",
        "  DeletionExecutorIdentity: {Value: !Sub 'lucy-${RealmSlug}-deletion-executor'}",
        count=1,
    )
    text = _replace(
        text,
        "Outputs:\n",
        "Outputs:\n"
        "  RealmSlug: {Value: !Ref RealmSlug}\n"
        "  TenantAccountUuid: {Value: !Ref TenantAccountUuid}\n"
        "  NodeId: {Value: !Ref NodeId}\n"
        "  NodeTenureId: {Value: !Ref NodeTenureId}\n"
        "  TenureEpoch: {Value: !Ref TenureEpoch}\n"
        "  SecurityRealmId: {Value: !Ref SecurityRealmId}\n"
        "  RealmWorkspaceUuid: {Value: !Ref RealmWorkspaceUuid}\n"
        "  DeploymentId: {Value: !Ref DeploymentId}\n"
        "  RealmBindingGeneration: {Value: !Ref RealmBindingGeneration}\n"
        "  NodeAuthzEpoch: {Value: !Ref NodeAuthzEpoch}\n",
        count=1,
    )
    return text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).with_name("security-baseline-v1.2.yaml"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    arguments = parser.parse_args()

    source = arguments.source.resolve(strict=True)
    output = arguments.output.resolve()
    if output.exists() and not arguments.force:
        raise FileExistsError(f"refusing to overwrite existing output: {output}")
    rendered = derive_v1_3(source.read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8", newline="")
    print(f"rendered {output} sha256={hashlib.sha256(rendered.encode()).hexdigest()}")


if __name__ == "__main__":
    main()
