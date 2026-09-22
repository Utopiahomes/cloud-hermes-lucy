"""Compose one serving process: authority, fence, executor, service and private API.

This is what a deployment runs. Everything a request depends on is built here, once, in a fixed
order, and nothing is shared with any previous process except the ledger:

1. ``start_serving`` reads the anchor, invokes the launcher when no claimant waits, and consumes
   exactly one claimant, which yields this process's fence and its runtime watch;
2. the executor holds that fence, that watch and a fresh volatile replay cache;
3. the service and the private API are built over it, with durable ``jti`` replay state;
4. while the process serves, the watch is refreshed on a fixed interval off the event loop;
5. on shutdown intake closes and the fence is drained and retired, so the next process starts
   through the launcher rather than by taking over.

A startup refusal is fatal: this module never retries its way into authority.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from lucy.shared_execution.api import ApiRelease, create_shared_execution_app
from lucy.shared_execution.auth import WorkloadIdentity, WorkloadJwtVerifier
from lucy.shared_execution.durable_executor import DurableExecutor, ExecutionRefused
from lucy.shared_execution.durable_service import (
    DurableExecutionService,
    ProfileAuthority,
    TransportProvider,
)
from lucy.shared_execution.idempotency import IdempotencyDigestRing
from lucy.shared_execution.postgres_ledger import (
    LedgerScope,
    PostgresExecutionLedger,
    PostgresJtiReplayStore,
    RecoveryWitness,
)
from lucy.shared_execution.recovery_anchor import ExternalRecoveryAnchor, RecoveryAnchorIdentity
from lucy.shared_execution.replay_cache import InMemoryReplayCache
from lucy.shared_execution.served_startup import ServedRuntime, start_serving
from lucy.shared_execution.service import ProviderTransport
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)

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
    profiles: ProfileAuthority
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


@dataclass(frozen=True)
class ServedApplication:
    app: FastAPI
    runtime: ServedRuntime
    executor: DurableExecutor


def build_served_app(
    configuration: ServedConfiguration,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ServedApplication:
    """Start one serving process, or raise ``ServedStartupRefused`` and start nothing."""

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
        profiles=configuration.profiles,
        digests=configuration.digests,
        clock=clock,
    )
    interval = configuration.refresh_interval.total_seconds()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        refresher = asyncio.create_task(_refresh_forever(runtime, interval))
        try:
            yield
        finally:
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
        service,
        WorkloadJwtVerifier(
            configuration.workload,
            PostgresJtiReplayStore(configuration.runtime_database_url),
        ),
        configuration.release,
        lifespan=lifespan,
    )
    return ServedApplication(app=app, runtime=runtime, executor=executor)


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
