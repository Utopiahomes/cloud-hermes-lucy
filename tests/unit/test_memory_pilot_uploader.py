from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from test_memory_pilot_transport import NOW, _authorization

from lucy.memory_pilot_intake_api import MemoryPilotExecutionResponseV1
from lucy.memory_pilot_transport import (
    MemoryPilotTransportBatchV1,
    prepare_memory_pilot_transport,
)
from lucy.memory_pilot_transport_runner import MemoryPilotTransportExecutionReceiptV1
from lucy.memory_pilot_uploader import PilotUploadUnavailable, SequentialMemoryPilotUploader


def _prepared():
    build, authorization = _authorization()
    return prepare_memory_pilot_transport(
        build,
        authorization,
        expected_bundle_digest=authorization.bundle_digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )


class Transport:
    def __init__(self, *, fail_once: bool = False) -> None:
        self.fail_once = fail_once
        self.calls: list[tuple[str, bytes, str, int]] = []

    def __call__(self, url: str, body: bytes, authorization: str, timeout_seconds: int) -> bytes:
        self.calls.append((url, body, authorization, timeout_seconds))
        if self.fail_once:
            self.fail_once = False
            raise TimeoutError("synthetic lost response")
        batch = MemoryPilotTransportBatchV1.model_validate_json(body)
        return (
            MemoryPilotExecutionResponseV1(
                receipt=MemoryPilotTransportExecutionReceiptV1(
                    campaign_id=batch.campaign_id,
                    batch_id=batch.batch_id,
                    extraction_job_id=batch.dispatch.extraction_job_id,
                    reservation_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    state="succeeded",
                    archived_source_count=len(batch.records),
                    billed_microusd=0,
                    candidate_count=0,
                ),
                review_artifact=None,
            )
            .model_dump_json()
            .encode()
        )


def test_sequential_https_upload_is_content_free_and_exact(tmp_path: Path) -> None:
    prepared = _prepared()
    reviews = tmp_path / "reviews"
    reviews.mkdir()
    transport = Transport()
    receipt = SequentialMemoryPilotUploader(
        endpoint="https://private-lucy.example", transport=transport
    ).upload(
        prepared,
        capability_token=b"c" * 32,
        intake_root=tmp_path,
        review_directory=reviews,
    )

    assert receipt.uploaded_batch_count == len(prepared.batches)
    assert receipt.succeeded_batch_count == len(prepared.batches)
    assert receipt.review_artifact_paths == ()
    assert all(call[0].startswith("https://") for call in transport.calls)
    assert all(call[2].startswith("Bearer ") for call in transport.calls)
    assert "private synthetic history" not in receipt.model_dump_json()


def test_lost_response_requires_same_identity_retry(tmp_path: Path) -> None:
    prepared = _prepared()
    reviews = tmp_path / "reviews"
    reviews.mkdir()
    transport = Transport(fail_once=True)
    uploader = SequentialMemoryPilotUploader(
        endpoint="https://private-lucy.example", transport=transport
    )
    with pytest.raises(PilotUploadUnavailable, match="exact-identity retry"):
        uploader.upload(
            prepared,
            capability_token=b"c" * 32,
            intake_root=tmp_path,
            review_directory=reviews,
        )
    receipt = uploader.upload(
        prepared,
        capability_token=b"c" * 32,
        intake_root=tmp_path,
        review_directory=reviews,
    )
    assert receipt.succeeded_batch_count == len(prepared.batches)
    assert transport.calls[0][1] == transport.calls[1][1]


def test_uploader_rejects_plain_http_and_output_outside_intake(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        SequentialMemoryPilotUploader(endpoint="http://private-lucy.example")
    for endpoint in (
        "https://private-lucy.example/path",
        "https://user@private-lucy.example",
        "https://private-lucy.example?realm=other",
        "https://private-lucy.example#fragment",
    ):
        with pytest.raises(ValueError, match="HTTPS origin"):
            SequentialMemoryPilotUploader(endpoint=endpoint)
    reviews = tmp_path.parent / "outside-reviews"
    reviews.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="inside the intake root"):
        SequentialMemoryPilotUploader(
            endpoint="https://private-lucy.example", transport=Transport()
        ).upload(
            _prepared(),
            capability_token=b"c" * 32,
            intake_root=tmp_path,
            review_directory=reviews,
        )
