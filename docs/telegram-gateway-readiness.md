# Telegram gateway readiness

Date: 2026-08-27

## Boundary

The `live-telegram` Compose profile uses the reviewed Hermes v0.20.5 image and
its supported `hermes gateway run` command. Hermes remains responsible for the
Telegram transport, stable numeric user allowlist, unauthorized-DM behavior,
and supervised gateway restart. No Hermes source is patched.

The Lucy profile permits only the `clarify` toolset on Telegram, ignores
unauthorized DMs, disables command execution, and routes model calls through
the Lucy control plugin and durable model budget.

## Startup gates

The gateway does not start until all of these conditions pass:

1. The secret-free profile has been seeded into the persistent `/opt/data`
   volume.
2. The keyless pinned-container plugin doctor imports and registers
   `lucy_control` successfully.
3. A separate credential-shape preflight confirms that the OpenRouter and Lucy
   adapter credentials are set, the Telegram bot token is structurally valid,
   the allowlist is nonempty and numeric, and the numeric home channel is in
   that allowlist. This preflight runs only after the plugin doctor succeeds.
4. The Lucy API is healthy and has completed Rejoining.

Hermes then receives the credentials and starts under the image's s6 supervision
with Docker restart policy `unless-stopped`. No gateway port is published; the
bot makes its outbound Telegram connection over the project network.

## Private local configuration

Set these values only in the Git-ignored repository-root `.env` file:

```dotenv
LUCY_ADAPTER_TOKEN=<long random local token shared by Hermes and Lucy>
TELEGRAM_BOT_TOKEN=<complete token from BotFather>
TELEGRAM_ALLOWED_USERS=<your numeric Telegram user ID>
TELEGRAM_HOME_CHANNEL=<the same numeric Telegram user ID>
```

Multiple explicitly trusted numeric IDs may be comma-separated in the
allowlist. A blank value, username, wildcard, duplicate, malformed token, or
home channel outside the allowlist is rejected. Do not paste the bot token into
source, documentation, a commit, or chat.

The existing `OPENROUTER_API_KEY` must also remain configured. The example
`LUCY_ADAPTER_TOKEN` placeholder is deliberately rejected for this live mode;
replace it with a long random local value before activation.

## Activation and acceptance

After the private values are present, start the gateway with:

```powershell
docker compose -f compose.yaml -f compose.hermes-spike.yaml --profile live-telegram up -d hermes-telegram-gateway
```

The live acceptance check should then prove one allowlisted synthetic message
gets exactly one budgeted response, an unknown account gets no response, a
restart preserves the session boundary without duplicate delivery, and no
secret appears in committed files or application logs.

This document records the ready-to-activate boundary; it does not claim the live
Telegram acceptance until those credential-dependent checks have run.

## Live evidence

On 2026-08-28 the guarded profile authenticated to Telegram, accepted one
allowlisted direct message, and returned a model response. The request produced
exactly one durable `model.infer.openrouter` action: 5,000 micro-USD was
reserved, OpenRouter reported 3,221 input tokens and 34 output tokens, and Lucy
settled 102 micro-USD with no remaining reservation.

The first attempt exposed a pinned-Hermes gateway discrepancy: the long-running
Telegram path omitted the configured custom-provider `extra_body` from the
middleware-visible request, so Lucy correctly blocked it with
`provider_policy_missing` and created no action or charge. Plugin version 1.0.1
closes that gap by injecting the canonical routing policy into the effective
outgoing request before independently revalidating the route immediately before
execution.

Restarting the supervised gateway preserved the completed action exactly once:
the model action count, spent total, and zero-reserved balance were unchanged
after the process returned. A final post-restart inbound message remains the
last interactive transport check before calling the live acceptance complete.
