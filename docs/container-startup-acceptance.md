# Container startup acceptance

Lucy now enforces Rejoining before the API process begins serving requests.

## Startup order

Compose starts digest-pinned PostgreSQL, waits for database health, runs the
one-shot Alembic migration container with the owner-only migration credential,
and starts the restricted application container only after migrations finish.
The application image reads the expected Hermes commit from the reviewed
`hermes.lock`; deployment supplies the independently observed commit.

`python -m lucy.runtime` executes Rejoining before starting Uvicorn. A failed
gate exits nonzero, allowing the supervisor to apply restart policy without ever
opening the HTTP service.

## Health semantics

- `GET /health` is process liveness only.
- `GET /ready` returns success only while the durable lifecycle is `READY`.
- Memory lookup independently enforces the same readiness condition and its
  adapter credential.
- The pinned Hermes compatibility service waits for API health rather than mere
  process creation.

## Acceptance evidence

The healthy Compose path ran migrations, completed Rejoining, became healthy,
and repeated the full gate successfully after a container restart. A disposable
container given an all-zero observed Hermes commit exited with status 1 and the
diagnostic `hermes_pin: mismatch`; Uvicorn never started. The resulting degraded
state was then recovered by restarting the correctly configured supervised
container, which returned to `READY` through Rejoining.

All credentials used in acceptance were synthetic runtime environment values.
Named PostgreSQL and Hermes profile volumes remained preserved.
