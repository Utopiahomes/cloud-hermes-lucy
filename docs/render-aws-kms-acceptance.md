# Render to AWS KMS acceptance

Date: 2026-08-29

Status: adapter and least-privilege policy templates implemented; no cloud
resources created and live transcript capture remains disabled.

## Boundary

Render remains Lucy's application host and Render PostgreSQL remains the
authoritative evidence and memory database. One AWS customer-managed symmetric
KMS key protects per-message data-encryption keys (DEKs). A DynamoDB table stores
only the KMS-wrapped DEKs and is the deletion-aware registry outside PostgreSQL.

AWS KMS does not retain the ciphertext blobs returned by `GenerateDataKey`.
Consequently KMS alone cannot delete one message protected by a shared master
key. Keeping wrapped DEKs in DynamoDB preserves the backup invariant: restoring
an old PostgreSQL backup cannot restore a deleted wrapped DEK from the live
registry.

## Render identity

The Lucy service receives only `AWS_ROLE_ARN`. Render supplies and rotates
`AWS_WEB_IDENTITY_TOKEN_FILE`; operators must not set that variable manually.
Boto3's standard web-identity provider exchanges that token for temporary AWS
credentials. Permanent `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values are
forbidden in Render.

The IAM trust policy binds the role to all three Render OIDC subject dimensions:
workspace, environment, and service. Its audience is exactly
`sts.amazonaws.com`.

## Runtime permissions

The runtime role has only:

- `kms:GenerateDataKey` and `kms:Decrypt` on Lucy's exact KMS key ARN, requiring
  encryption context `application=cloud-hermes-lucy` plus the evidence UUID;
- `dynamodb:GetItem`, `PutItem`, and `DeleteItem` on Lucy's exact wrapped-key
  table ARN.

It cannot list or scan the registry, administer or schedule deletion of the KMS
key, create grants, change IAM, restore a table, or access any other AWS resource.
Key administration must use a separate human-controlled identity.

OIDC removes long-lived AWS credentials; it does not make a compromised running
service harmless. Code executing inside the authorized Lucy service could use
its temporary role until that session expires. The narrow key/table resources,
encryption-context policy, Render service subject, CloudTrail monitoring, and
the application approval boundary limit that exposure.

## Data flow

For each retained message:

1. Lucy calls `GenerateDataKey` with the evidence UUID in the encryption context.
2. KMS returns one plaintext 256-bit DEK and its KMS-wrapped ciphertext blob.
3. Lucy encrypts the message locally with AES-256-GCM and discards the plaintext
   DEK after use.
4. PostgreSQL receives message ciphertext, nonce, metadata, and an opaque key
   reference. DynamoDB receives the wrapped DEK under that reference.
5. Retrieval fetches the wrapped DEK by exact UUID and calls KMS `Decrypt` with
   the same encryption context.
6. Deletion removes the DynamoDB item before tombstoning PostgreSQL and
   invalidating every derived artifact.

The keyed commitment key is a separate 256-bit Render secret. It is not capable
of decrypting evidence or assuming an AWS role. Rotate it only through a reviewed
commitment migration because existing commitments depend on it.

## Required Render variables

```text
LUCY_ARCHIVE_BACKEND=aws-kms-dynamodb
LUCY_AWS_KMS_KEY_ARN=<full customer-managed KMS key ARN>
LUCY_AWS_DYNAMODB_KEY_TABLE=<exact table name>
LUCY_ARCHIVE_COMMITMENT_KEY_B64=<32 random bytes, base64 encoded>
AWS_REGION=<the KMS and DynamoDB region>
AWS_ROLE_ARN=<the Render-specific IAM role ARN>
```

Do not configure `AWS_WEB_IDENTITY_TOKEN_FILE`; Render creates it during deploy.

## Cloud acceptance gate

Before transcript capture is activated, a synthetic Render deployment must prove:

1. the caller identity is the expected assumed role and no static AWS credential
   variables exist;
2. one synthetic message can generate, store, retrieve, and decrypt a DEK;
3. a swapped evidence UUID fails because the KMS encryption context differs;
4. deleting the DynamoDB record makes the ciphertext undecryptable;
5. restoring PostgreSQL alone does not restore the wrapped DEK;
6. the role cannot list the DynamoDB table or call KMS/IAM administration APIs;
7. CloudTrail records the expected KMS calls and no unexpected resource use;
8. startup reconciliation finishes a simulated crash after DynamoDB deletion;
9. all existing local, PostgreSQL, and pinned-Hermes checks still pass; and
10. the owner approves activation after reviewing the evidence.

The templates under `deploy/aws` are inert examples. Substitute exact account,
workspace, environment, service, region, role, key, and table identifiers only
inside the AWS and Render control planes; do not commit those deployment values.
