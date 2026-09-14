# R1 cumulative coverage registry

Status: accepted for the commissioned Utopia R1 technical boundary on 2026-09-11.
This registry preserves all 72 test IDs from the Node/Tenancy v1.1 specification.
It does not relabel future R2 or R3 behavior as implemented.

Classification meanings:

- `PASSED_CURRENT`: exercised against the current source or commissioned boundary.
- `REUSED_WITH_DRIFT_CHECK`: earlier passing evidence remains valid after checking
  the code, configuration, identity, schema, or deployed resource that could invalidate it.
- `DEFERRED_NOT_IMPLEMENTED`: the feature belongs to R2/R3 and its endpoint is absent.

| Test IDs | Classification | R1 evidence or reason |
| --- | --- | --- |
| ISO-01, ISO-03, ISO-04, ISO-05, ISO-06, ISO-07, ISO-08 | REUSED_WITH_DRIFT_CHECK | R1-1/R1-2 identity, ingress, public projection, realm-session, scoped-memory, privacy, and negative-isolation suites; current API allowlist, deployed identity, schema, and privacy drift checks passed. |
| ISO-02 | PASSED_CURRENT | Commissioned PostgreSQL verification proved fixed login bindings, no unsafe role membership, removed schema-create authority, isolated admission ACLs, and denied direct table authority. |
| PUB-01, PUB-02, PUB-03, PUB-04 | REUSED_WITH_DRIFT_CHECK | R1-1 public projection tests cover exact binding, immutable approved snapshots, withdrawal, and visitor isolation; the current route inventory and capture-disabled deployment preserve the boundary. |
| PUB-05 | DEFERRED_NOT_IMPLEMENTED | Transfer/rehosting is R3; no transfer or rehost route exists. |
| SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, SEC-08 | REUSED_WITH_DRIFT_CHECK | R1-2 three-realm synthetic isolation, canonical-contract, replay, revocation-race, deletion-closure, and known-ID residual-risk evidence; AWS, SQL, artifact, and schema drift checks passed. |
| SEC-07 | PASSED_CURRENT | Current AWS verifier passed 51 exact account/stack/OIDC/IAM/KMS/Lambda/DynamoDB/CloudTrail checks; commissioned SQL verification passed role and table denials. |
| CAP-01, CAP-02, CAP-03, CAP-04 | REUSED_WITH_DRIFT_CHECK | Current authority, grant replay/idempotency, revocation, unavailable-authority, and recovery tests remain valid; deployed journal heads, recovery identities, schema, and admission state were rechecked. |
| JOB-01, JOB-02, JOB-03, JOB-04, JOB-05, JOB-06, JOB-07, JOB-08 | DEFERRED_NOT_IMPLEMENTED | Durable asynchronous jobs are R2; no jobs route exists. R1's bounded synchronous provider-attempt controller is covered separately. |
| WAL-01, WAL-02, WAL-03, WAL-04, WAL-05, WAL-06, WAL-07, WAL-08, WAL-09, WAL-10 | DEFERRED_NOT_IMPLEMENTED | Functional wallets and settlement are R2. R1 wallet IDs remain nonspendable and its narrower provider-cost admission is covered by R1-3 evidence. |
| GRANT-01, GRANT-02, GRANT-03 | DEFERRED_NOT_IMPLEMENTED | Cross-node consulting grants are R3; no consulting or grants route exists. |
| TOOL-01, TOOL-02 | DEFERRED_NOT_IMPLEMENTED | Tenant-scoped connector/OAuth tools are R3; no customer connector route exists. |
| RUN-01, RUN-02, RUN-03, RUN-04 | DEFERRED_NOT_IMPLEMENTED | Local runners are R3; no runner route exists. |
| LIFE-01 | REUSED_WITH_DRIFT_CHECK | Idempotent Utopia provisioning/bootstrap and retry evidence remains valid after stack, schema, role, and Render resource inventory checks. |
| LIFE-02, LIFE-03, LIFE-04, LIFE-05 | DEFERRED_NOT_IMPLEMENTED | Rehosting, transfer, export/import, and full offboarding are R3; corresponding routes are absent. Suspension and quarantine remain available as R1 operational controls. |
| REC-01, REC-02, REC-03, REC-05, REC-06, REC-07, REC-08 | REUSED_WITH_DRIFT_CHECK | R1-4 protected restore/replay, cross-realm denial, authority overlay, acknowledgement ambiguity, gap quarantine, finality, and capture-safety evidence remains valid after current AWS, Render, PostgreSQL, source, and schema checks. |
| REC-04 | DEFERRED_NOT_IMPLEMENTED | Full wallet funding/settlement recovery is R2. The implemented R1 provider-exposure reservation subset passed protected recovery without a provider call. |
| COMP-01, COMP-02, COMP-03, COMP-04, COMP-05 | REUSED_WITH_DRIFT_CHECK | R1 process/credential separation and documented realm-scoped residual risks remain valid after deployed identity, no-static-credential, privacy, route, and database checks. |
| COMP-06 | PASSED_CURRENT | Current AWS trust, role, policy, artifact, and exact OIDC binding verification passed; the Render inventory found no static AWS credentials. |
| DEFER-01 | PASSED_CURRENT | The exact current API route inventory contains no peer, token, wallet, consulting, runner, export, rehost, transfer, or StoinNet execution endpoint. |

The current focused cumulative run executed 74 R1 tests. Broader earlier evidence is
reused only where its invalidation conditions remain false. R2 and R3 rows become
`RETEST_REQUIRED` when their implementation begins; endpoint absence is the R1 control,
not evidence that their future positive behavior works.
