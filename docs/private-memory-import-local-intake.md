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

## Current gate

Creating an inventory and saving a pilot selection are local inspection. The selection is
explicitly marked `proposed_not_authorized`; it does not authorize upload, extraction, provider
processing, spending, or memory promotion. The exact record manifest also remains
`proposed_not_authorized`. Ray must separately authorize its final digest, provider/model route,
versions, scope, expiry, retries, and total spend before any selected record leaves this computer.
The full ZIP is never uploaded.
