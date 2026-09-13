# Private Lucy local import intake

The local intake boundary is:

`C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\<export-date>\`

The folder is outside the Cloud Lucy repository and the configured OneDrive root. Its inherited
Windows ACL is disabled; only the current Windows user and `SYSTEM` have access. The local
manifest fingerprint key is stored separately at:

`C:\Users\Forti\Private\cloud-lucy-imports\keys\manifest-fingerprint-v1.key`

Do not copy the key into `.env`, Git, Telegram, Render, or a model prompt. Volume encryption
could not be confirmed programmatically on this workstation, so Windows Device Encryption or
BitLocker status remains a manual prerequisite before personal exports are placed here.

## Place an export

1. Download the ChatGPT export ZIP without extracting it.
2. Create a folder named for the export date, such as
   `C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\`.
3. Move the untouched ZIP into that folder. Do not place it in the repository or OneDrive.
4. Keep the original ZIP unchanged. The inventory command reads entries directly and does not
   extract them.

## Run a local inventory

From the repository root in PowerShell, replace the date and ZIP filename:

```powershell
.\.venv\Scripts\python.exe -m lucy.memory_import_cli inventory `
  --zip "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\export.zip" `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --fingerprint-key-file "C:\Users\Forti\Private\cloud-lucy-imports\keys\manifest-fingerprint-v1.key" `
  --output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\inventory.v1.json"
```

The report remains local. It includes conversation titles, dates, branch/message counts,
attachment inventory, malformed/missing-data counts, byte/token estimates, advisory topic tags,
and a keyed archive commitment. It deliberately excludes message bodies. Topic tags organize
review only and never select a realm or grant authority.

The parser rejects archives with unsafe paths, symbolic links, encrypted entries, duplicate
normalized names, suspicious compression ratios, or configured size/count/depth violations.
It performs no network calls and does not fetch referenced URLs.

## Review a pilot selection locally

Create a random local console token once and keep it out of the repository:

```powershell
$tokenPath = "C:\Users\Forti\Private\cloud-lucy-imports\keys\console-session-v1.token"
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllText($tokenPath, [Convert]::ToHexString($bytes))
```

Then start the review console, replacing the date and private content-scope UUID with the
commissioned Raymond-private values:

```powershell
.\.venv\Scripts\python.exe -m lucy.memory_import_console `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --inventory "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\inventory.v1.json" `
  --selection-output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-selection.v1.json" `
  --session-token-file $tokenPath `
  --destination-content-scope-id "replace-with-raymond-private-content-scope-uuid"
```

Open `http://127.0.0.1:8765/imports`. The console listens only on loopback, requires the local
session token, rejects untrusted hosts and request origins, sends no-store browser headers, and
renders imported titles as text rather than executable markup. Select 12–20 conversations and
set a hard model-spend ceiling, attempt ceiling, and expiry. The saved file is immutable and
digest-bound to the inventory, destination, selection, estimates, and limits.

## Expand the selection into exact records

After reviewing the conversation-level proposal, bind every supported selected message and every
explicit exclusion into one campaign manifest. Set the extractor, prompt, provider-policy, and
model-route versions to the exact values proposed for the pilot; these examples are deliberately
not defaults:

```powershell
$campaignId = [guid]::NewGuid()
$extractorVersion = "replace-with-reviewed-extractor-version"
$promptVersion = "replace-with-reviewed-prompt-version"
$providerPolicyId = "replace-with-reviewed-provider-policy-id"
$modelRoute = "replace-with-reviewed-openrouter-route"

.\.venv\Scripts\python.exe -m lucy.memory_import_cli manifest `
  --zip "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\export.zip" `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --fingerprint-key-file "C:\Users\Forti\Private\cloud-lucy-imports\keys\manifest-fingerprint-v1.key" `
  --inventory "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\inventory.v1.json" `
  --selection "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-selection.v1.json" `
  --output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-manifest.v1.json" `
  --campaign-id $campaignId `
  --extractor-version $extractorVersion `
  --prompt-version $promptVersion `
  --provider-policy-id $providerPolicyId `
  --model-route $modelRoute
```

This command makes no network or model call. It rechecks the ZIP commitment and selection digest,
preserves native conversation/node/message IDs, roles, timestamps, displayed and alternate
branches, and parent relationships, and emits keyed commitments rather than message text. The
first pilot explicitly excludes attachment contents and unsupported message records. The output
contains one campaign manifest, matching the database's one-manifest-per-campaign boundary.

## Record the separate exact pilot authorization

Do this only after Ray has reviewed and separately authorized the displayed bundle digest, scope,
provider/model route, versions, expiry, retry ceiling, and total spend ceiling. The approval
reference identifies that out-of-band owner decision; creating the earlier manifest is not
approval. Replace every placeholder, including the exact digest printed by the manifest command:

```powershell
$bundleDigest = "replace-with-reviewed-64-character-bundle-digest"
$approvalRef = "replace-with-owner-approval-uuid"
$approvedAt = (Get-Date).ToUniversalTime().ToString("o")
$confirmation = "AUTHORIZE PRIVATE LUCY PILOT $bundleDigest"

.\.venv\Scripts\python.exe -m lucy.memory_import_cli authorize `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --manifest "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-manifest.v1.json" `
  --expected-bundle-digest $bundleDigest `
  --owner-approval-ref $approvalRef `
  --owner-actor-id "replace-with-private-owner-actor-id" `
  --approved-at $approvedAt `
  --confirmation $confirmation `
  --output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-authorization.v1.json"
```

The authorization artifact is still plaintext-free. It embeds the exact reviewed bundle and may
permit only archive and extraction. It cannot approve candidates, promote memory, expand the
source set, change the destination, change the provider route, or increase any limit.

## Run the no-network execution preflight

Immediately before execution, rebuild the bundle from the untouched ZIP and compare it with the
exact authorization. This detects a changed export, inventory, selection, fingerprint key,
campaign, route, or limit before any archive, database, AWS, OpenRouter, or spending effect:

```powershell
.\.venv\Scripts\python.exe -m lucy.memory_import_cli preflight `
  --zip "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\export.zip" `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --fingerprint-key-file "C:\Users\Forti\Private\cloud-lucy-imports\keys\manifest-fingerprint-v1.key" `
  --inventory "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\inventory.v1.json" `
  --selection "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-selection.v1.json" `
  --authorization "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-authorization.v1.json" `
  --expected-bundle-digest $bundleDigest `
  --output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-preflight.v1.json"
```

The content-free preflight report says only whether that exact campaign is ready. It performs no
upload or provider request. The effect-bearing runner repeats the same authorization and expiry
check before its first archive write; an expired or non-exact authorization has zero side effects.

## Register the exact authorization with the operator identity

Registration is a distinct operator step. It does not upload the ZIP, call AWS or OpenRouter, or
start extraction. It lets the isolated policy service recognize only the exact authorization that
already passed owner approval and a fresh no-network preflight. Run it only in a protected operator
session where `LUCY_MIGRATION_DATABASE_URL` is already supplied through the deployment secret
boundary; do not paste or save that URL in the intake folder or repository:

```powershell
$registrationConfirmation = "REGISTER PRIVATE LUCY PILOT $bundleDigest"

.\.venv\Scripts\python.exe -m lucy.memory_import_cli register `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --authorization "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-authorization.v1.json" `
  --preflight "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-preflight.v1.json" `
  --expected-bundle-digest $bundleDigest `
  --confirmation $registrationConfirmation `
  --output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-registration.v1.json"
```

The preflight must be no more than 15 minutes old and still unexpired. PostgreSQL recomputes the
bundle digest against its exact campaign before recording an immutable allowlist entry. Routine
Lucy and the policy service cannot perform this registration. The content-free receipt can be
replayed, but a changed authorization conflicts rather than widening the prior approval.

## Prepare and register exact transport commitments

This step still does not upload plaintext or call a model. Create a separate random transfer key
and campaign capability under the protected intake root. They are campaign-scoped secrets, not the
permanent fingerprint key; never place them in the repository or a synchronized folder. The
transfer key is delivered separately to the private realm-evidence service, while the capability
stays with the Windows uploader. The production secret-delivery and uploader steps are not yet
commissioned.

```powershell
$transportExpiry = (Get-Date).ToUniversalTime().AddMinutes(30).ToString("o")
$transportPlan = "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\transport-plan.v1.json"

.\.venv\Scripts\python.exe -m lucy.memory_import_cli transport-plan `
  --zip "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\export.zip" `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --fingerprint-key-file "C:\Users\Forti\Private\cloud-lucy-imports\keys\manifest-fingerprint-v1.key" `
  --transfer-key-file "C:\Users\Forti\Private\cloud-lucy-imports\keys\pilot-transfer-v1.key" `
  --capability-token-file "C:\Users\Forti\Private\cloud-lucy-imports\keys\pilot-capability-v1.token" `
  --inventory "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\inventory.v1.json" `
  --selection "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-selection.v1.json" `
  --authorization "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\pilot-authorization.v1.json" `
  --expected-bundle-digest $bundleDigest `
  --maximum-microusd-per-attempt 0 `
  --timeout-seconds 30 `
  --expires-at $transportExpiry `
  --output $transportPlan

$transportConfirmation = "REGISTER PRIVATE LUCY TRANSPORT $bundleDigest"
.\.venv\Scripts\python.exe -m lucy.memory_import_cli transport-register `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --registration $transportPlan `
  --expected-bundle-digest $bundleDigest `
  --confirmation $transportConfirmation `
  --output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\transport-registration-receipt.v1.json"
```

The plan contains record IDs, request identities, size ceilings, and cryptographic commitments,
but no conversation text. PostgreSQL sees only that content-free plan. During the later upload,
the service will obtain the exact manifest from PostgreSQL, verify the uploaded batch HMAC and
canonical provider request in memory, and durably admit it once. A wrong capability, wrong key,
altered batch, expired campaign, or revoked transport fails before provider execution.

## Review extracted memory candidates locally

After an authorized extraction worker has produced `candidates.v1.json`, start the separate
candidate console. The candidate artifact contains only the finite candidate set, explicit
candidate digests, and exact source excerpts already bound to archived evidence; it is not the
original ZIP. Replace the actor ID with the commissioned private-owner identity:

```powershell
.\.venv\Scripts\python.exe -m lucy.memory_candidate_review_console `
  --intake-root "C:\Users\Forti\Private\cloud-lucy-imports" `
  --bundle "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\candidates.v1.json" `
  --proposal-output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\candidate-review-proposal.v1.json" `
  --authorization-output "C:\Users\Forti\Private\cloud-lucy-imports\chatgpt\2026-09-12\candidate-review-authorization.v1.json" `
  --session-token-file $tokenPath `
  --owner-actor-id "replace-with-private-owner-actor-id"
```

Open `http://127.0.0.1:8766/review`. First choose one disposition for every exact candidate and
create a non-authorizing proposal. The console then displays the final exact proposal, including
any new candidate version created by an ordinary-projection or uncertainty change. Only the
second step, using the displayed confirmation phrase, creates the immutable owner-authorization
artifact. It does not stage, approve in PostgreSQL, promote, or expose a candidate to normal
recall. The policy workflow must still verify the artifact and exact candidate digest at those
separate boundaries.

## Current gate

Creating an inventory and saving a pilot selection are local inspection. The selection is
explicitly marked `proposed_not_authorized`; it does not authorize upload, extraction, provider
processing, spending, or memory promotion. The exact record manifest also remains
`proposed_not_authorized`. Ray must separately authorize its final digest, provider/model route,
versions, scope, expiry, retries, and total spend before any selected record leaves this computer.
The full ZIP is never uploaded.

Candidate review follows the same separation: proposal generation is not authorization, and a
local authorization artifact is not automatic promotion. Rejection and deferral carry no
approvable candidate bytes. Acceptance as ordinary private or marking uncertain creates a new
exact candidate version, so an earlier digest cannot authorize the transformed result.

The private-memory OpenRouter adapter remains inert until the separately authorized pilot is run.
The deployment-ready recovery assembly keeps the signer in `lucy-policy`: routine Lucy authenticates
to that private service for one signed exact-job recovery grant and invokes only the configured,
qualified AWS Lambda alias. Its request contract fixes the reviewed model route, requires
strict JSON Schema support,
enforces per-request zero-data-retention and denied data collection, sends no tools or plugins,
bounds output tokens and response bytes, and requires provider-reported usage cost. The generation
identifier is retained only as a keyed commitment. A provider/model/privacy mismatch, malformed
output, missing cost, token overrun, or ambiguous transport failure closes the attempt without
returning candidate content. Real provider processing and spend still require separate pilot
authorization.
