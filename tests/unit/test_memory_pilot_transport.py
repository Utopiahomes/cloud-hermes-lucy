from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from lucy.chatgpt_manifest import (
    AuthorizedPilotManifestV1,
    LocalChatGPTConversationV1,
    LocalChatGPTMessageV1,
    LocalPilotBuildV1,
    PilotManifestBundleV1,
    manifest_record_for_local_message,
)
from lucy.memory_import import ImportManifestV2
from lucy.memory_pilot_compiler import (
    compile_memory_pilot_batches,
    compile_memory_pilot_dispatch,
)
from lucy.memory_pilot_transport import (
    MemoryPilotTransportUnavailable,
    PostgresMemoryPilotTransportAdmission,
    capability_token_digest,
    prepare_memory_pilot_transport,
    validate_memory_pilot_transport_batch,
)

NOW = datetime(2026, 9, 12, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


def _build(count: int) -> LocalPilotBuildV1:
    messages = tuple(
        LocalChatGPTMessageV1(
            source_record_id=f"conversation:node-{index}:message-{index}",
            conversation_id="conversation",
            native_node_id=f"node-{index}",
            native_message_id=f"message-{index}",
            parent_source_record_id=None,
            native_role="user",
            role="owner",
            occurred_at=NOW,
            displayed=True,
            content=f"Record {index}: " + ("private synthetic history " * 40),
            inclusion_state="included",
        )
        for index in range(count)
    )
    records = tuple(manifest_record_for_local_message(item, b"f" * 32) for item in messages)
    manifest = ImportManifestV2(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="pilot:selection",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="private-zdr-v1",
        model_route="openai/gpt-oss-20b",
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        records=records,
        max_records=count,
        max_bytes=sum(item.byte_length for item in records),
        max_source_estimated_tokens=sum(item.estimated_tokens for item in records),
        max_request_input_tokens=1_000_000,
        max_request_output_tokens=200,
        max_request_total_tokens=1_000_200,
        max_model_spend_microusd=10_000,
        max_attempts=4,
        expires_at=NOW + timedelta(days=1),
    )
    return LocalPilotBuildV1(
        bundle=PilotManifestBundleV1(
            selection_proposal_digest="a" * 64,
            archive_commitment="b" * 64,
            campaign_id=CAMPAIGN,
            destination_content_scope_id=SCOPE,
            manifest=manifest,
            included_record_count=count,
            excluded_record_count=0,
            included_source_bytes=manifest.max_bytes,
            estimated_source_tokens=manifest.max_source_estimated_tokens,
            excluded_attachment_reference_count=0,
        ),
        conversations=(
            LocalChatGPTConversationV1(conversation_id="conversation", messages=messages),
        ),
    )


def _authorization() -> tuple[LocalPilotBuildV1, AuthorizedPilotManifestV1]:
    build = _build(2)
    authorization = AuthorizedPilotManifestV1(
        bundle=build.bundle,
        bundle_digest=build.bundle.digest,
        owner_approval_ref="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        owner_actor_id="raymond-owner",
        approved_at=NOW,
    )
    return build, authorization


def test_prepare_is_deterministic_content_free_registration_and_exact_batches() -> None:
    build, authorization = _authorization()
    prepared = prepare_memory_pilot_transport(
        build,
        authorization,
        expected_bundle_digest=authorization.bundle_digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
        expires_at=NOW + timedelta(hours=1),
        now=NOW + timedelta(minutes=1),
    )
    replay = prepare_memory_pilot_transport(
        build,
        authorization,
        expected_bundle_digest=authorization.bundle_digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
        expires_at=NOW + timedelta(hours=1),
        now=NOW + timedelta(minutes=1),
    )
    assert prepared == replay
    serialized = prepared.model_dump(mode="json")
    assert "private synthetic history" not in str(serialized["registration"])
    assert "batches" not in serialized
    assert prepared.registration.capability_token_digest == capability_token_digest(b"c" * 32)
    manifest = authorization.bundle.manifest
    for batch, expected in zip(
        prepared.batches, prepared.registration.batches, strict=True
    ):
        validate_memory_pilot_transport_batch(
            batch,
            manifest=manifest,
            expected=expected,
            transfer_key=b"t" * 32,
        )


def test_batch_rejects_plaintext_or_dispatch_tampering_and_wrong_key() -> None:
    build, authorization = _authorization()
    prepared = prepare_memory_pilot_transport(
        build,
        authorization,
        expected_bundle_digest=authorization.bundle_digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
        expires_at=NOW + timedelta(hours=1),
        now=NOW + timedelta(minutes=1),
    )
    batch = prepared.batches[0]
    expected = prepared.registration.batches[0]
    manifest = authorization.bundle.manifest
    changed_record = batch.records[0].model_copy(update={"content": "same byte count-ish"})
    changed = batch.model_copy(update={"records": (changed_record, *batch.records[1:])})
    with pytest.raises(ValueError, match="registered admission|byte length|dispatch"):
        validate_memory_pilot_transport_batch(
            changed,
            manifest=manifest,
            expected=expected,
            transfer_key=b"t" * 32,
        )
    changed_dispatch = batch.model_copy(
        update={
            "dispatch": batch.dispatch.model_copy(
                update={"maximum_microusd": batch.dispatch.maximum_microusd + 1}
            )
        }
    )
    with pytest.raises(ValueError, match="canonical|commitment"):
        validate_memory_pilot_transport_batch(
            changed_dispatch,
            manifest=manifest,
            expected=expected,
            transfer_key=b"t" * 32,
        )
    with pytest.raises(ValueError, match="commitment"):
        validate_memory_pilot_transport_batch(
            batch,
            manifest=manifest,
            expected=expected,
            transfer_key=b"w" * 32,
        )

    original = batch.records[0]
    substituted = original.model_copy(update={"content": "X" + original.content[1:]})
    substituted_records = (substituted, *batch.records[1:])
    manifest_by_source = {item.source_record_id: item for item in manifest.records}
    local = {
        item.source_record_id: LocalChatGPTMessageV1(
            source_record_id=item.source_record_id,
            conversation_id="transport-substitution",
            native_node_id=item.native_node_id or item.source_record_id,
            native_message_id=item.native_message_id or item.source_record_id,
            parent_source_record_id=item.parent_source_record_id,
            native_role=item.native_role or item.role,
            role=item.role,
            occurred_at=item.occurred_at,
            displayed=item.displayed,
            source_revision=item.source_revision,
            content=item.content,
            inclusion_state="included",
        )
        for item in substituted_records
    }
    rebuilt_dispatch = compile_memory_pilot_dispatch(
        manifest,
        tuple(manifest_by_source[item.source_record_id] for item in substituted_records),
        local,
        batch_index=batch.batch_index,
        maximum_microusd=batch.dispatch.maximum_microusd,
        timeout_seconds=batch.dispatch.timeout_seconds,
    )
    substituted_batch = batch.model_copy(
        update={"records": substituted_records, "dispatch": rebuilt_dispatch}
    )
    substituted_metadata = expected.model_copy(
        update={
            "extraction_job_id": rebuilt_dispatch.extraction_job_id,
            "request_commitment": rebuilt_dispatch.request_commitment,
            "transport_bytes": substituted_batch.byte_length,
        }
    )
    with pytest.raises(ValueError, match="commitment"):
        validate_memory_pilot_transport_batch(
            substituted_batch,
            manifest=manifest,
            expected=substituted_metadata,
            transfer_key=b"t" * 32,
        )


def test_prepare_rejects_expired_or_overlong_transport_and_short_secrets() -> None:
    build, authorization = _authorization()
    for expiry in (NOW, datetime(2026, 9, 14, tzinfo=UTC)):
        with pytest.raises(ValueError, match="campaign window"):
            prepare_memory_pilot_transport(
                build,
                authorization,
                expected_bundle_digest=authorization.bundle_digest,
                transfer_key=b"t" * 32,
                capability_token=b"c" * 32,
                maximum_microusd_per_attempt=1_000,
                timeout_seconds=30,
                expires_at=expiry,
                now=NOW,
            )
    with pytest.raises(ValueError, match="transfer key"):
        prepare_memory_pilot_transport(
            build,
            authorization,
            expected_bundle_digest=authorization.bundle_digest,
            transfer_key=b"short",
            capability_token=b"c" * 32,
            maximum_microusd_per_attempt=1_000,
            timeout_seconds=30,
            expires_at=NOW + timedelta(hours=1),
            now=NOW,
        )


def test_compiler_remains_the_source_of_exact_dispatch_identity() -> None:
    build, _authorization_value = _authorization()
    compilation = compile_memory_pilot_batches(
        build,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
    )
    assert all(batch.extraction_job_id for batch in compilation.batches)


class _Result:
    def __init__(self, value: dict[str, object]) -> None:
        self._value = value

    def scalar_one(self) -> dict[str, object]:
        return self._value


class _Session:
    def __init__(
        self,
        results: list[dict[str, object]],
        statements: list[str],
        parameters: list[object],
    ) -> None:
        self._results = results
        self._statements = statements
        self._parameters = parameters

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, statement: object, parameters: object) -> _Result:
        self._statements.append(str(statement))
        self._parameters.append(parameters)
        return _Result(self._results.pop(0))


class _Sessions:
    def __init__(self, results: list[dict[str, object]]) -> None:
        self.results = results
        self.statements: list[str] = []
        self.parameters: list[object] = []

    def begin(self) -> _Session:
        return _Session(self.results, self.statements, self.parameters)


def test_admission_sends_only_content_free_values_to_postgres() -> None:
    build, authorization = _authorization()
    prepared = prepare_memory_pilot_transport(
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
    registration = prepared.registration
    batch = prepared.batches[0]
    expected: dict[str, object] = {
        "campaign_id": str(registration.campaign_id),
        "owner_approval_ref": str(registration.owner_approval_ref),
        "destination_content_scope_id": str(registration.destination_content_scope_id),
        "bundle_digest": registration.bundle_digest,
        "manifest_digest": registration.manifest_digest,
        "transfer_key_commitment": registration.transfer_key_commitment,
        "expires_at": registration.expires_at.isoformat(),
        "manifest": authorization.bundle.manifest.model_dump(mode="json"),
        "batch": registration.batches[0].model_dump(mode="json"),
    }
    receipt: dict[str, object] = {
        "batch_id": str(batch.batch_id),
        "admitted_at": NOW.isoformat(),
        "replayed": False,
    }
    sessions = _Sessions([expected, receipt])
    result = PostgresMemoryPilotTransportAdmission(  # type: ignore[arg-type]
        sessions, transfer_key=b"t" * 32
    ).admit(
        batch,
        capability_token=b"c" * 32,
    )
    assert result.batch_id == batch.batch_id
    assert len(sessions.statements) == 2
    assert all("private synthetic history" not in item for item in sessions.statements)
    assert "private synthetic history" not in str(sessions.parameters)


def test_admission_rejects_wrong_runtime_transfer_key_before_claim() -> None:
    build, authorization = _authorization()
    prepared = prepare_memory_pilot_transport(
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
    registration = prepared.registration
    batch = prepared.batches[0]
    expected: dict[str, object] = {
        "campaign_id": str(registration.campaign_id),
        "owner_approval_ref": str(registration.owner_approval_ref),
        "destination_content_scope_id": str(registration.destination_content_scope_id),
        "bundle_digest": registration.bundle_digest,
        "manifest_digest": registration.manifest_digest,
        "transfer_key_commitment": registration.transfer_key_commitment,
        "expires_at": registration.expires_at.isoformat(),
        "manifest": authorization.bundle.manifest.model_dump(mode="json"),
        "batch": registration.batches[0].model_dump(mode="json"),
    }
    sessions = _Sessions([expected])
    with pytest.raises(MemoryPilotTransportUnavailable):
        PostgresMemoryPilotTransportAdmission(  # type: ignore[arg-type]
            sessions, transfer_key=b"w" * 32
        ).admit(
            batch,
            capability_token=b"c" * 32,
        )
    assert len(sessions.statements) == 1


def test_admission_rejects_cross_campaign_payload_before_claim() -> None:
    build, authorization = _authorization()
    prepared = prepare_memory_pilot_transport(
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
    registration = prepared.registration
    batch = prepared.batches[0].model_copy(
        update={"campaign_id": UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")}
    )
    expected: dict[str, object] = {
        "campaign_id": str(registration.campaign_id),
        "owner_approval_ref": str(registration.owner_approval_ref),
        "destination_content_scope_id": str(registration.destination_content_scope_id),
        "bundle_digest": registration.bundle_digest,
        "manifest_digest": registration.manifest_digest,
        "transfer_key_commitment": registration.transfer_key_commitment,
        "expires_at": registration.expires_at.isoformat(),
        "manifest": authorization.bundle.manifest.model_dump(mode="json"),
        "batch": registration.batches[0].model_dump(mode="json"),
    }
    sessions = _Sessions([expected])
    with pytest.raises(MemoryPilotTransportUnavailable):
        PostgresMemoryPilotTransportAdmission(  # type: ignore[arg-type]
            sessions, transfer_key=b"t" * 32
        ).admit(batch, capability_token=b"c" * 32)
    assert len(sessions.statements) == 1
