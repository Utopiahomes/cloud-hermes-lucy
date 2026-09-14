"""Bounded activation contract for private Telegram Stage 1."""

from __future__ import annotations

import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TelegramStage1Artifacts(_StrictModel):
    source_commit: str
    rollback_commit: str
    gateway_dockerfile_sha256: str
    profile_sha256: str
    hermes_release: Literal["v2026.8.19"]
    hermes_version: Literal["0.20.5"]
    hermes_source_commit: Literal["fcbd1076a93841fa88855acce810e342a5b78101"]
    hermes_manifest_digest: Literal[
        "3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09"
    ]
    hermes_platform_digest: Literal[
        "f3cba556e7b35dbe20a67d32b715090d9babd5907798c79721380757d9a12bb6"
    ]
    target_platform: Literal["linux/amd64"]
    schema_revision: Literal["0053_r1_telegram_authority"]

    @model_validator(mode="after")
    def validate_hashes(self) -> TelegramStage1Artifacts:
        if any(
            _GIT_SHA.fullmatch(value) is None
            for value in (self.source_commit, self.rollback_commit)
        ):
            raise ValueError("source and rollback commits must be full lowercase Git SHAs")
        if any(
            _SHA256.fullmatch(value) is None
            for value in (self.gateway_dockerfile_sha256, self.profile_sha256)
        ):
            raise ValueError("artifact hashes must be lowercase SHA-256 values")
        return self


class TelegramStage1Realm(_StrictModel):
    node_id: UUID
    security_realm_id: UUID
    content_scope_id: UUID
    channel_binding_id: UUID
    routine_render_service_id: str = Field(pattern=r"^srv-[a-z0-9]+$")
    gateway_render_service_id: str = Field(pattern=r"^srv-[a-z0-9]+$")


class TelegramStage1Budget(_StrictModel):
    provider: Literal["openrouter"]
    model: Literal["openai/gpt-oss-20b"]
    reservation_microusd: Literal[5000]
    max_output_tokens: Literal[1024]
    realm_daily_limit_microusd: Literal[1000000]


class TelegramStage1ActivationManifest(_StrictModel):
    contract: Literal["lucy.telegram.private.stage1.activation.v1"]
    environment: Literal["production"]
    realm_slug: Literal["utopia"]
    activation_decision_id: str = Field(min_length=1, max_length=256)
    artifacts: TelegramStage1Artifacts
    realm: TelegramStage1Realm
    bot_id: int = Field(gt=0)
    owner_telegram_user_id: int = Field(gt=0)
    one_active_gateway: Literal[True]
    unauthorized_dm_behavior: Literal["ignore"]
    budget: TelegramStage1Budget
    transcript_capture_enabled: Literal[False]
    automatic_memory_writes_enabled: Literal[False]
    raw_evidence_retrieval_enabled: Literal[False]
    rollback_preserves_authority_and_deletion_history: Literal[True]


class TelegramStage2Artifacts(_StrictModel):
    source_commit: str
    rollback_commit: str
    gateway_dockerfile_sha256: str
    profile_sha256: str
    hermes_release: Literal["v2026.8.19"]
    hermes_version: Literal["0.20.5"]
    hermes_source_commit: Literal["fcbd1076a93841fa88855acce810e342a5b78101"]
    hermes_manifest_digest: Literal[
        "3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09"
    ]
    hermes_platform_digest: Literal[
        "f3cba556e7b35dbe20a67d32b715090d9babd5907798c79721380757d9a12bb6"
    ]
    target_platform: Literal["linux/amd64"]
    schema_revision: Literal["0054_stage2_scoped_turn_commit"]

    @model_validator(mode="after")
    def validate_hashes(self) -> TelegramStage2Artifacts:
        if any(
            _GIT_SHA.fullmatch(value) is None
            for value in (self.source_commit, self.rollback_commit)
        ):
            raise ValueError("source and rollback commits must be full lowercase Git SHAs")
        if any(
            _SHA256.fullmatch(value) is None
            for value in (self.gateway_dockerfile_sha256, self.profile_sha256)
        ):
            raise ValueError("artifact hashes must be lowercase SHA-256 values")
        return self


class TelegramStage2ActivationManifest(_StrictModel):
    """Fail-closed production promotion contract for encrypted Telegram capture."""

    contract: Literal["lucy.telegram.private.stage2.activation.v1"]
    environment: Literal["production"]
    realm_slug: Literal["utopia"]
    activation_decision_id: str = Field(min_length=1, max_length=256)
    artifacts: TelegramStage2Artifacts
    realm: TelegramStage1Realm
    bot_id: int = Field(gt=0)
    owner_telegram_user_id: int = Field(gt=0)
    one_active_gateway: Literal[True]
    unauthorized_dm_behavior: Literal["ignore"]
    budget: TelegramStage1Budget
    transcript_capture_enabled: Literal[True]
    encrypted_evidence_archive_enabled: Literal[True]
    authoritative_two_message_commit: Literal[True]
    off_record_history_rotation: Literal[True]
    automatic_memory_writes_enabled: Literal[False]
    raw_evidence_retrieval_enabled: Literal[False]
    sensitive_gateway_tools_enabled: Literal[False]
    rollback_preserves_authority_and_deletion_history: Literal[True]
