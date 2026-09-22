"""Compose one serving process: authority, fence, executor, service and private API.

This is what a deployment runs. Everything a request depends on is built in the application's
lifespan startup, once, in a fixed order, and nothing is shared with any previous process except
the ledger:

1. ``start_serving`` reads the anchor, invokes the launcher when no claimant waits, and consumes
   exactly one claimant, which yields this process's fence and its runtime watch;
2. the executor holds that fence, that watch and a fresh volatile replay cache;
3. the service takes the current profile only from signed releases verified against the pinned
   release root, and the private API verifies callers against durable ``jti`` replay state;
4. while the process serves, the watch is refreshed on a fixed interval off the event loop;
5. on shutdown intake closes and the fence is drained and retired, so the next process starts
   through the launcher rather than by taking over.

Startup happens in the lifespan rather than when the application object is built, so an object
that is built but never served takes no claimant. A startup refusal fails the server's startup:
this module never retries its way into authority.

Run exactly one serving process per environment. RC1 v1 has a single admission and replay
coordinator; a second worker would take its own fence and fence the first one out. Do not run
this under ``--workers`` greater than one or ``--reload``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from lucy.shared_execution.api import ApiRelease, create_shared_execution_app
from lucy.shared_execution.auth import WorkloadIdentity, WorkloadJwtVerifier
from lucy.shared_execution.durable_executor import DurableExecutor, ExecutionRefused
from lucy.shared_execution.durable_service import DurableExecutionService, TransportProvider
from lucy.shared_execution.idempotency import IdempotencyDigestRing
from lucy.shared_execution.postgres_authority import PostgresSignedAuthorityStore
from lucy.shared_execution.postgres_ledger import (
    LedgerScope,
    PostgresExecutionLedger,
    PostgresJtiReplayStore,
    RecoveryWitness,
)
from lucy.shared_execution.recovery_anchor import ExternalRecoveryAnchor, RecoveryAnchorIdentity
from lucy.shared_execution.replay_cache import InMemoryReplayCache
from lucy.shared_execution.served_startup import ServedRuntime, start_serving
from lucy.shared_execution.service import ExecutionRejected, ProviderTransport
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)
from lucy.shared_execution.verified_profiles import VerifiedProfileAuthority
from lucy.shared_execution.wire import ExecutionRequest, ExecutionResponse

logger = logging.getLogger(__name__)


@dataclass(frozen=True, repr=False)
class ServedConfiguration:
    """Everything one serving process needs. Database URLs carry credentials; never log this."""

    anchor: ExternalRecoveryAnchor
    anchor_identity: RecoveryAnchorIdentity
    runtime_database_url: str
    recovery_database_url: str
    recovery_generation: int
    scope: LedgerScope
    workload: WorkloadIdentity
    authority_issuer: str
    release_root_key_id: str
    release_root_public_key: Ed25519PublicKey
    digests: IdempotencyDigestRing
    transport: ProviderTransport
    release: ApiRelease
    refresh_interval: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if (
            self.anchor_identity.environment != self.scope.environment
            or self.recovery_generation < 1
            or not timedelta(seconds=1) <= self.refresh_interval <= timedelta(minutes=5)
        ):
            raise ValueError("served configuration is invalid")

    def __repr__(self) -> str:
        return "ServedConfiguration(credentials=redacted)"


class _Process:
    """What lifespan startup built, and the service requests reach once it exists.

    Before startup completes and after shutdown begins, a request is answered with
    state_store_unavailable: there is no fence it could be admitted under.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._service: DurableExecutionService | None = None
        self.runtime: ServedRuntime | None = None
        self.executor: DurableExecutor | None = None

    def bind(
        self, service: DurableExecutionService, runtime: ServedRuntime, executor: DurableExecutor
    ) -> None:
        with self._lock:
            self._service, self.runtime, self.executor = service, runtime, executor

    def close(self) -> None:
        with self._lock:
            self._service = None

    def execute(
        self,
        *,
        caller: str,
        idempotency_key: str,
        request_id: UUID,
        request: ExecutionRequest,
        timeout_ms: int | None = None,
        received_at: datetime | None = None,
    ) -> ExecutionResponse:
        with self._lock:
            service = self._service
        if service is None:
            raise ExecutionRejected("state_store_unavailable")
        return service.execute(
            caller=caller,
            idempotency_key=idempotency_key,
            request_id=request_id,
            request=request,
            timeout_ms=timeout_ms,
            received_at=received_at,
        )


@dataclass(frozen=True)
class ServedApplication:
    app: FastAPI
    process: _Process

    @property
    def runtime(self) -> ServedRuntime:
        if self.process.runtime is None:
            raise RuntimeError("the process has not started serving")
        return self.process.runtime

    @property
    def executor(self) -> DurableExecutor:
        if self.process.executor is None:
            raise RuntimeError("the process has not started serving")
        return self.process.executor


def build_served_app(
    configuration: ServedConfiguration,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ServedApplication:
    """Build the application. Its lifespan starts serving, or fails startup and serves nothing."""

    process = _Process()
    interval = configuration.refresh_interval.total_seconds()

    def start() -> None:
        ledger = PostgresExecutionLedger(
            configuration.runtime_database_url,
            RecoveryWitness(
                environment=configuration.anchor_identity.environment,
                storage_epoch=configuration.anchor_identity.storage_epoch,
                recovery_generation=configuration.recovery_generation,
            ),
        )
        runtime = start_serving(
            anchor=configuration.anchor,
            identity=configuration.anchor_identity,
            issuer=StartupAttestationIssuer(
                anchor=configuration.anchor,
                identity=configuration.anchor_identity,
                recovery_database_url=configuration.recovery_database_url,
                checkpoint_source=LedgerRecoveryCheckpointSource(
                    configuration.recovery_database_url
                ),
            ),
            ledger=ledger,
            clock=clock,
        )
        executor = DurableExecutor(
            ledger=ledger,
            scope=configuration.scope,
            coordinator_generation=runtime.coordinator_generation,
            provider=TransportProvider(configuration.transport),
            watch=runtime.watch,
            replay_cache=InMemoryReplayCache(clock=clock),
        )
        service = DurableExecutionService(
            executors={configuration.workload.subject: executor},
            profiles=VerifiedProfileAuthority(
                store=PostgresSignedAuthorityStore(configuration.runtime_database_url),
                scope=configuration.scope,
                authority_issuer=configuration.authority_issuer,
                root_key_id=configuration.release_root_key_id,
                root_public_key=configuration.release_root_public_key,
                clock=clock,
            ),
            digests=configuration.digests,
            clock=clock,
        )
        process.bind(service, runtime, executor)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await run_in_threadpool(start)
        runtime, executor = process.runtime, process.executor
        assert runtime is not None and executor is not None
        refresher = asyncio.create_task(_refresh_forever(runtime, interval))
        try:
            yield
        finally:
            process.close()
            refresher.cancel()
            with suppress(asyncio.CancelledError):
                await refresher
            try:
                await run_in_threadpool(executor.shutdown)
            except ExecutionRefused:
                # Work is still in flight or the fence already moved. The process exits either
                # way; unsettled records stay liabilities for the reaper and reconciliation.
                logger.warning("tiamat_retirement_refused")

    app = create_shared_execution_app(
        process,
        WorkloadJwtVerifier(
            configuration.workload,
            PostgresJtiReplayStore(configuration.runtime_database_url),
        ),
        configuration.release,
        lifespan=lifespan,
    )
    return ServedApplication(app=app, process=process)


async def _refresh_forever(runtime: ServedRuntime, interval: float) -> None:
    """Refresh the watch until cancelled. A closed latch stays closed; refresh cannot reopen it."""

    while True:
        await asyncio.sleep(interval)
        try:
            outcome = await run_in_threadpool(runtime.watch.refresh)
        except Exception:  # noqa: BLE001 - an unexpected refresh failure must not end the loop
            # The watch itself treats an unreadable anchor as no change; anything else unexpected
            # is logged without content and the claimant's expiry still bounds this process.
            logger.exception("tiamat_anchor_refresh_failed")
            continue
        if outcome != "authority_current":
            logger.warning("tiamat_anchor_refresh outcome=%s", outcome)
