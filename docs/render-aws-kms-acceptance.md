# Render/AWS Security Baseline v1.1 acceptance

Date: 2026-08-29

Status: local implementation passes; cloud resources have not been provisioned.
Transcript capture remains disabled.

## Provisioning order

1. Create the owner's AWS account and enable phishing-resistant root MFA and
   recovery factors. In IAM Identity Center `us-east-1`, create and permanently
   assign a `LucySecurityAdministrator` permission set to the owner's group.
   Use that federated identity for routine setup; never create root or human
   access keys. Preserve the assignment so AWS does not delete its generated
   role.
2. Use a Render workspace that supports managed AWS OIDC. Create one production
   environment and four private services from
   `deploy/render/security-baseline-v1.1.yaml.example`. Record the workspace,
   environment, and immutable service IDs.
3. In AWS `us-east-1`, create the Render workspace OIDC provider and deploy
   `deploy/aws/security-baseline-v1.1.yaml` with those exact IDs, the
   `AWSReservedSSO_LucySecurityAdministrator_*` role ARN pattern, and an owner
   alert email. Confirm the SNS subscription. Confirm that the template's
   stable `lucy-kms-recovery-administrator` role can be assumed only by that
   permission set.
4. Configure each returned role ARN on only its matching Render service. The
   policy service must have no AWS role or static AWS credentials.
5. Generate independent adapter, owner, policy-gateway, commitment, and Ed25519
   signing secrets. Policy receives the private signing key; evidence/deletion
   receive only the public key.
6. Create distinct production database logins, apply
   `deploy/postgres/production_roles.sql.example`, and use private Render
   database URLs. Keep the migration owner credential outside runtime.
7. Connect Hermes to all four private URLs with independent tokens. Do not
   enable transcript capture.

## Positive acceptance

- All services start in their declared `LUCY_SERVICE_MODE` and reject endpoints
  belonging to other identities.
- Archive generates a DEK and stores one wrapped key but cannot decrypt history.
- During an allowlisted owner turn, policy issues one signed exact-record permit
  and evidence consumes it to decrypt one synthetic message.
- The same permit/idempotency replay succeeds; another action, reason, record,
  or idempotency key is denied.
- Deletion removes only the synthetic record's wrapped key and completes the
  database cascade without any KMS permission.
- PostgreSQL restoration after key destruction cannot decrypt the message.
  Missing-key recovery completes exactly once after a simulated crash.
- A 30-day PostgreSQL backup restores into an isolated recovery database; RPO
  and RTO are recorded.

## Negative authorization acceptance

Use IAM policy simulation or harmless read-only calls. Never test denial by
actually invoking key disable/deletion, database deletion, or backup deletion.

- Archive denies `kms:Decrypt`, DynamoDB `GetItem`/`DeleteItem`/`Scan`, table
  deletion, and every IAM/KMS administration action.
- Evidence denies `GenerateDataKey`, DynamoDB `PutItem`/`DeleteItem`/`Scan`, bulk
  export, and every administration action.
- Deletion denies every KMS action, DynamoDB `PutItem`/`Scan`/table deletion,
  and every administration action.
- Policy has no web-identity/static AWS variables or callable AWS identity.
- Every runtime database login denies DDL, role/schema creation, backup actions,
  and access outside its documented tables.

## Observability and privacy acceptance

- CloudTrail contains expected `GenerateDataKey` and `Decrypt` records with no
  unexpected principal/resource.
- A controlled non-production policy-change event reaches the confirmed owner
  SNS destination; destructive key events are not exercised.
- Application logs contain no synthetic transcript, candidate credential,
  plaintext/wrapped DEK, commitment/signing key, database password, Telegram
  token, or OpenRouter key.
- Provider routing still requires zero data retention and denied data collection.

## Final report

Record the AWS account/region, Render environment/service IDs, KMS key ARN and
rotation state, IAM role ARNs, DynamoDB table, CloudTrail trail, alert
confirmation, image tag/digests, migration head, test outputs, restoration
RPO/RTO, exceptions, and rollback procedure. Never include secrets or transcript
plaintext.

Only the owner may approve live Telegram transcript capture after reviewing the
report.
