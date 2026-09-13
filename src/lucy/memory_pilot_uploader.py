"""Protected Windows uploader for exact private-memory pilot batches."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_pilot_intake_api import MemoryPilotExecutionResponseV1
from lucy.memory_pilot_transport import PreparedMemoryPilotTransportV1


class PilotUploadUnavailable(RuntimeError):
    """The exact batch response could not be established safely."""


class PilotBatchHttpTransport(Protocol):
    def __call__(
        self, url: str, body: bytes, authorization: str, timeout_seconds: int
    ) -> bytes: ...


class MemoryPilotUploadReceiptV1(BaseModel):
    """Content-free local summary; review artifacts remain separate files."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: str
    uploaded_batch_count: int = Field(ge=1)
    succeeded_batch_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    review_artifact_paths: tuple[str, ...]


class SequentialMemoryPilotUploader:
    def __init__(
        self,
        *,
        endpoint: str,
        transport: PilotBatchHttpTransport | None = None,
        maximum_response_bytes: int = 10_000_000,
    ) -> None:
        normalized = endpoint.rstrip("/")
        if not normalized.startswith("https://"):
            raise ValueError("pilot upload endpoint must use HTTPS")
        if not 1 <= maximum_response_bytes <= 10_000_000:
            raise ValueError("pilot response ceiling is invalid")
        self._endpoint = normalized
        self._transport = transport or _https_post
        self._maximum_response_bytes = maximum_response_bytes

    def upload(
        self,
        prepared: PreparedMemoryPilotTransportV1,
        *,
        capability_token: bytes,
        intake_root: Path,
        review_directory: Path,
        timeout_seconds: int = 120,
    ) -> MemoryPilotUploadReceiptV1:
        if len(capability_token) != 32:
            raise ValueError("pilot capability must contain exactly 32 bytes")
        if not 1 <= timeout_seconds <= 600:
            raise ValueError("pilot upload timeout is invalid")
        root = intake_root.resolve(strict=True)
        destination = review_directory.resolve(strict=True)
        if not destination.is_dir() or not destination.is_relative_to(root):
            raise ValueError("pilot review directory must exist inside the intake root")
        authorization = "Bearer " + base64.urlsafe_b64encode(capability_token).decode(
            "ascii"
        ).rstrip("=")
        paths: list[str] = []
        succeeded = 0
        candidate_count = 0
        for batch in prepared.batches:
            try:
                raw = self._transport(
                    f"{self._endpoint}/v1/private-memory/pilot/batches/{batch.batch_id}",
                    canonical_json_bytes(batch),
                    authorization,
                    timeout_seconds,
                )
                if not raw or len(raw) > self._maximum_response_bytes:
                    raise ValueError("pilot response is outside its byte ceiling")
                response = MemoryPilotExecutionResponseV1.model_validate_json(raw)
            except Exception as exc:
                raise PilotUploadUnavailable(
                    f"pilot batch {batch.batch_index} requires exact-identity retry"
                ) from exc
            if (
                response.receipt.campaign_id != batch.campaign_id
                or response.receipt.batch_id != batch.batch_id
                or response.receipt.extraction_job_id != batch.dispatch.extraction_job_id
            ):
                raise PilotUploadUnavailable("pilot response identity is invalid")
            succeeded += response.receipt.state == "succeeded"
            candidate_count += response.receipt.candidate_count
            if response.review_artifact is not None:
                artifact_path = destination / (
                    f"batch-{batch.batch_index:04d}-{batch.batch_id}.review.json"
                )
                _write_or_verify_exact(artifact_path, response.review_artifact)
                paths.append(str(artifact_path))
        return MemoryPilotUploadReceiptV1(
            campaign_id=str(prepared.registration.campaign_id),
            uploaded_batch_count=len(prepared.batches),
            succeeded_batch_count=succeeded,
            candidate_count=candidate_count,
            review_artifact_paths=tuple(paths),
        )


def _write_or_verify_exact(path: Path, value: object) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    try:
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        if path.read_bytes() != payload:
            raise PilotUploadUnavailable(
                "existing review artifact conflicts with replay"
            ) from exc


def _https_post(url: str, body: bytes, authorization: str, timeout_seconds: int) -> bytes:
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cache-Control": "no-store",
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            return bytes(response.read(10_000_001))
    except (HTTPError, URLError, TimeoutError) as exc:
        raise PilotUploadUnavailable("pilot HTTPS request failed") from exc
