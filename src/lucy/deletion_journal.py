"""Independent, append-only accepted deletion intents (local acceptance provider).

The journal is authoritative; PostgreSQL receipts are disposable acknowledgments.
No transcript, ciphertext, wrapped key, or plaintext fingerprint belongs here.
SQLite is NOT the production multi-service security boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal, Protocol
from uuid import UUID, uuid4

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Connection, text

from lucy.authorization import SensitiveAction, SensitiveActionPermitV1

GENESIS = "0" * 64
DYNAMO_CHUNK_BYTES = 200_000
DYNAMO_MAX_CHUNKS = 12


class DeletionJournalError(RuntimeError):
    """Content-free failure; callers must keep storage closed."""


class DeletionTargetV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID
    key_ref: UUID | None  # None only for an already tombstoned descendant.


class DeletionIntentV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    intent_id: UUID
    journal_id: UUID
    registry_id: UUID
    operation_id: UUID
    idempotency_key: str = Field(min_length=1, max_length=512)
    evidence_id: UUID
    reason: Literal["owner_request", "sensitive_data", "retention_expired"]
    accepted_at: datetime
    permit: SensitiveActionPermitV1
    targets: tuple[DeletionTargetV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_authority(self) -> DeletionIntentV1:
        permit = self.permit
        if (
            self.accepted_at.tzinfo is None
            or not permit.issued_at <= self.accepted_at < permit.expires_at
            or permit.action != SensitiveAction.EVIDENCE_DELETE
            or permit.evidence_ids != (self.evidence_id,)
            or permit.max_records != 1
            or permit.reason != self.reason
        ):
            raise ValueError("deletion intent does not match accepted owner authority")
        ids = [target.evidence_id for target in self.targets]
        refs = [target.key_ref for target in self.targets if target.key_ref is not None]
        if ids != sorted(set(ids)) or self.evidence_id not in ids or len(refs) != len(set(refs)):
            raise ValueError("deletion intent targets must be canonical and unique")
        return self


class JournalHead(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    journal_id: UUID
    registry_id: UUID
    sequence: int = Field(ge=0)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class JournalEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    previous_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    intent: DeletionIntentV1


class DeletionJournal(Protocol):
    def __hash__(self) -> int: ...

    def head(self) -> JournalHead: ...

    def entry(self, sequence: int) -> JournalEntry: ...

    def append(self, intent: DeletionIntentV1, expected: JournalHead) -> JournalEntry: ...


class DynamoJournalClient(Protocol):
    def get_item(self, **kwargs: object) -> dict[str, object]: ...

    def transact_write_items(self, **kwargs: object) -> dict[str, object]: ...


def _serialized(intent: DeletionIntentV1) -> str:
    return json.dumps(intent.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _digest(sequence: int, previous: str, body: str) -> str:
    # Integrity linkage over an opaque, content-free manifest, NOT a plaintext hash.
    return hashlib.sha256(f"lucy-deletion-v1:{sequence}:{previous}:{body}".encode()).hexdigest()


class SqliteDeletionJournal:
    """Explicitly initialized local journal; opening a missing store never creates it.

    Atomic append uses BEGIN IMMEDIATE and synchronous=FULL. The hash chain detects
    accidental corruption; it does NOT authenticate a malicious filesystem writer.
    Protected local files/approved writer are trusted in this acceptance provider.
    """

    def __init__(self, path: Path, *, journal_id: UUID, registry_id: UUID) -> None:
        if not path.is_absolute():
            raise DeletionJournalError("journal path must be absolute")
        self._path = path
        self._journal_id = journal_id
        self._registry_id = registry_id

    @classmethod
    def initialize(cls, path: Path, *, registry_id: UUID) -> SqliteDeletionJournal:
        if not path.is_absolute() or not path.parent.is_dir():
            raise DeletionJournalError("journal directory must already exist")
        # Exclusive creation: never overwrite an existing journal (including empty files).
        with path.open("xb"):
            pass
        journal_id = uuid4()
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript("""
                CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    journal_id TEXT NOT NULL, registry_id TEXT NOT NULL);
                CREATE TABLE intents (sequence INTEGER PRIMARY KEY,
                    previous_digest TEXT NOT NULL, digest TEXT NOT NULL UNIQUE,
                    intent_id TEXT NOT NULL UNIQUE, operation_key TEXT NOT NULL UNIQUE,
                    body TEXT NOT NULL);
                CREATE TRIGGER intents_no_update BEFORE UPDATE ON intents
                    BEGIN SELECT RAISE(ABORT, 'append only'); END;
                CREATE TRIGGER intents_no_delete BEFORE DELETE ON intents
                    BEGIN SELECT RAISE(ABORT, 'append only'); END;
                CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity
                    BEGIN SELECT RAISE(ABORT, 'immutable identity'); END;
                CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity
                    BEGIN SELECT RAISE(ABORT, 'immutable identity'); END;
            """)
            connection.execute(
                "INSERT INTO identity VALUES (1,?,?)",
                (
                    str(journal_id),
                    str(registry_id),
                ),
            )
        return cls(path, journal_id=journal_id, registry_id=registry_id)

    def _connect(self, *, write: bool = False) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._path.as_uri() + ("?mode=rw" if write else "?mode=ro"),
                uri=True,
                timeout=5,
            )
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.Error:
            raise DeletionJournalError("deletion journal unavailable") from None

    def _head(self, connection: sqlite3.Connection) -> JournalHead:
        identity = connection.execute("SELECT journal_id,registry_id FROM identity").fetchall()
        if identity != [(str(self._journal_id), str(self._registry_id))]:
            raise DeletionJournalError("deletion journal identity mismatch")
        row = connection.execute(
            "SELECT sequence,digest FROM intents ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return JournalHead(
            journal_id=self._journal_id,
            registry_id=self._registry_id,
            sequence=row[0] if row else 0,
            digest=row[1] if row else GENESIS,
        )

    def head(self) -> JournalHead:
        try:
            with closing(self._connect()) as connection:
                return self._head(connection)
        except (sqlite3.Error, ValueError):
            raise DeletionJournalError("deletion journal unavailable or invalid") from None

    def entry(self, sequence: int) -> JournalEntry:
        try:
            with closing(self._connect()) as connection:
                self._head(connection)
                row = connection.execute(
                    "SELECT previous_digest,digest,body FROM intents WHERE sequence=?",
                    (sequence,),
                ).fetchone()
            if row is None or _digest(sequence, row[0], row[2]) != row[1]:
                raise DeletionJournalError("deletion journal entry missing or corrupt")
            intent = DeletionIntentV1.model_validate_json(row[2])
            if (intent.journal_id, intent.registry_id) != (self._journal_id, self._registry_id):
                raise DeletionJournalError("deletion intent identity mismatch")
            return JournalEntry(
                sequence=sequence, previous_digest=row[0], digest=row[1], intent=intent
            )
        except (sqlite3.Error, ValueError):
            raise DeletionJournalError("deletion journal entry unavailable or invalid") from None

    def append(self, intent: DeletionIntentV1, expected: JournalHead) -> JournalEntry:
        if (intent.journal_id, intent.registry_id) != (self._journal_id, self._registry_id):
            raise DeletionJournalError("deletion intent identity mismatch")
        try:
            with closing(self._connect(write=True)) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                if self._head(connection) != expected:
                    raise DeletionJournalError("deletion journal advanced; recovery required")
                sequence = expected.sequence + 1
                body = _serialized(intent)
                digest = _digest(sequence, expected.digest, body)
                connection.execute(
                    "INSERT INTO intents VALUES (?,?,?,?,?,?)",
                    (
                        sequence,
                        expected.digest,
                        digest,
                        str(intent.intent_id),
                        intent.idempotency_key,
                        body,
                    ),
                )
            return JournalEntry(
                sequence=sequence,
                previous_digest=expected.digest,
                digest=digest,
                intent=intent,
            )
        except sqlite3.Error:
            # Outcome may be ambiguous. Never destroy keys or assume append failed.
            raise DeletionJournalError(
                "deletion journal append unconfirmed; recovery required"
            ) from None


class AwsDynamoDeletionJournal:
    """Production journal using an atomic head update plus immutable intent chunks.

    Head and entry reads are strongly consistent. Runtime readers receive only
    the head-table permission; the deletion identity alone can read/append intent
    chunks. DynamoDB administration, backup restore, and table replacement remain
    outside every service role.
    """

    def __init__(
        self,
        client: DynamoJournalClient,
        *,
        head_table: str,
        intent_table: str,
        journal_id: UUID,
        registry_id: UUID,
    ) -> None:
        if not _valid_table_name(head_table) or not _valid_table_name(intent_table):
            raise ValueError("invalid DynamoDB deletion journal table name")
        if head_table == intent_table:
            raise ValueError("journal head and intent tables must be separate")
        self._client = client
        self._head_table = head_table
        self._intent_table = intent_table
        self._journal_id = journal_id
        self._registry_id = registry_id

    @classmethod
    def from_environment(cls) -> AwsDynamoDeletionJournal:
        try:
            journal_id = UUID(os.environ["LUCY_DELETION_JOURNAL_ID"])
            registry_id = UUID(os.environ["LUCY_ARCHIVE_REGISTRY_ID"])
            head_table = os.environ["LUCY_AWS_DELETION_HEAD_TABLE"]
            intent_table = os.environ["LUCY_AWS_DELETION_INTENT_TABLE"]
        except (KeyError, ValueError):
            raise DeletionJournalError(
                "production deletion journal configuration is incomplete"
            ) from None
        return _aws_journal(_aws_region(), head_table, intent_table, journal_id, registry_id)

    def head(self) -> JournalHead:
        try:
            response = self._client.get_item(
                TableName=self._head_table,
                Key={"journal_key": {"S": "HEAD"}},
                ConsistentRead=True,
                ProjectionExpression="#j,#r,#s,#d",
                ExpressionAttributeNames={
                    "#j": "journal_id",
                    "#r": "registry_id",
                    "#s": "sequence",
                    "#d": "digest",
                },
            )
            item = response.get("Item")
            if not isinstance(item, dict):
                raise DeletionJournalError("deletion journal head is unavailable")
            head = JournalHead(
                journal_id=UUID(_dynamo_string(item, "journal_id")),
                registry_id=UUID(_dynamo_string(item, "registry_id")),
                sequence=int(_dynamo_number(item, "sequence")),
                digest=_dynamo_string(item, "digest"),
            )
            if (head.journal_id, head.registry_id) != (
                self._journal_id,
                self._registry_id,
            ):
                raise DeletionJournalError("deletion journal identity mismatch")
            return head
        except DeletionJournalError:
            raise
        except (BotoCoreError, ClientError, TypeError, ValueError):
            raise DeletionJournalError(
                "production deletion journal head unavailable or invalid"
            ) from None

    def entry(self, sequence: int) -> JournalEntry:
        if sequence < 1:
            raise DeletionJournalError("deletion journal sequence is invalid")
        prefix = _sequence_prefix(sequence)
        try:
            meta = self._get_intent_item(f"{prefix}#meta")
            parts = int(_dynamo_number(meta, "parts"))
            if not 1 <= parts <= DYNAMO_MAX_CHUNKS:
                raise DeletionJournalError("deletion journal entry part count is invalid")
            body = b"".join(
                _dynamo_binary(self._get_intent_item(f"{prefix}#{part:03d}"), "body")
                for part in range(parts)
            ).decode("utf-8")
            previous = _dynamo_string(meta, "previous_digest")
            digest = _dynamo_string(meta, "digest")
            if _digest(sequence, previous, body) != digest:
                raise DeletionJournalError("deletion journal entry is corrupt")
            intent = DeletionIntentV1.model_validate_json(body)
            if (
                intent.journal_id,
                intent.registry_id,
                str(intent.intent_id),
            ) != (
                self._journal_id,
                self._registry_id,
                _dynamo_string(meta, "intent_id"),
            ):
                raise DeletionJournalError("deletion journal entry identity mismatch")
            return JournalEntry(
                sequence=sequence,
                previous_digest=previous,
                digest=digest,
                intent=intent,
            )
        except DeletionJournalError:
            raise
        except (BotoCoreError, ClientError, UnicodeDecodeError, TypeError, ValueError):
            raise DeletionJournalError(
                "production deletion journal entry unavailable or invalid"
            ) from None

    def append(self, intent: DeletionIntentV1, expected: JournalHead) -> JournalEntry:
        if (intent.journal_id, intent.registry_id) != (
            self._journal_id,
            self._registry_id,
        ):
            raise DeletionJournalError("deletion intent identity mismatch")
        if self.head() != expected:
            raise DeletionJournalError("deletion journal advanced; recovery required")
        sequence = expected.sequence + 1
        body = _serialized(intent)
        encoded = body.encode("utf-8")
        chunks = tuple(
            encoded[offset : offset + DYNAMO_CHUNK_BYTES]
            for offset in range(0, len(encoded), DYNAMO_CHUNK_BYTES)
        )
        if not chunks or len(chunks) > DYNAMO_MAX_CHUNKS:
            raise DeletionJournalError("deletion intent exceeds the reviewed cloud journal limit")
        digest = _digest(sequence, expected.digest, body)
        prefix = _sequence_prefix(sequence)
        transaction: list[dict[str, object]] = [
            {
                "Update": {
                    "TableName": self._head_table,
                    "Key": {"journal_key": {"S": "HEAD"}},
                    "UpdateExpression": "SET #s=:next,#d=:next_digest,#i=:intent",
                    "ConditionExpression": (
                        "#j=:journal AND #r=:registry AND #s=:expected AND #d=:digest"
                    ),
                    "ExpressionAttributeNames": {
                        "#j": "journal_id",
                        "#r": "registry_id",
                        "#s": "sequence",
                        "#d": "digest",
                        "#i": "intent_id",
                    },
                    "ExpressionAttributeValues": {
                        ":journal": {"S": str(self._journal_id)},
                        ":registry": {"S": str(self._registry_id)},
                        ":expected": {"N": str(expected.sequence)},
                        ":digest": {"S": expected.digest},
                        ":next": {"N": str(sequence)},
                        ":next_digest": {"S": digest},
                        ":intent": {"S": str(intent.intent_id)},
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._intent_table,
                    "Item": {
                        "journal_id": {"S": str(self._journal_id)},
                        "entry_key": {"S": f"{prefix}#meta"},
                        "sequence": {"N": str(sequence)},
                        "previous_digest": {"S": expected.digest},
                        "digest": {"S": digest},
                        "intent_id": {"S": str(intent.intent_id)},
                        "parts": {"N": str(len(chunks))},
                    },
                    "ConditionExpression": "attribute_not_exists(journal_id)",
                }
            },
        ]
        transaction.extend(
            {
                "Put": {
                    "TableName": self._intent_table,
                    "Item": {
                        "journal_id": {"S": str(self._journal_id)},
                        "entry_key": {"S": f"{prefix}#{part:03d}"},
                        "body": {"B": chunk},
                    },
                    "ConditionExpression": "attribute_not_exists(journal_id)",
                }
            }
            for part, chunk in enumerate(chunks)
        )
        try:
            self._client.transact_write_items(
                TransactItems=transaction,
                ClientRequestToken=str(intent.intent_id),
                ReturnConsumedCapacity="NONE",
            )
        except (BotoCoreError, ClientError):
            # A network/client error can arrive after DynamoDB committed. Recover
            # only the exact immutable record; never infer success from key loss.
            try:
                observed = self.entry(sequence)
                if observed.digest == digest and observed.intent == intent:
                    return observed
            except DeletionJournalError:
                pass
            raise DeletionJournalError(
                "deletion journal append unconfirmed; recovery required"
            ) from None
        return JournalEntry(
            sequence=sequence,
            previous_digest=expected.digest,
            digest=digest,
            intent=intent,
        )

    def _get_intent_item(self, entry_key: str) -> dict[str, object]:
        response = self._client.get_item(
            TableName=self._intent_table,
            Key={
                "journal_id": {"S": str(self._journal_id)},
                "entry_key": {"S": entry_key},
            },
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, dict):
            raise DeletionJournalError("deletion journal entry is incomplete")
        return item


def check_journal_admission(
    connection: Connection, journal: DeletionJournal | None
) -> JournalHead | None:
    binding = connection.execute(
        text("SELECT journal_id,registry_id FROM lucy.deletion_journal_binding WHERE singleton")
    ).one_or_none()
    if binding is None:
        if journal is not None:
            raise DeletionJournalError("deletion journal requires operator binding")
        # Only unbound low-level development tests may omit the provider. HTTP
        # entry points always require a provider, even before the first deletion.
        return None
    if journal is None:
        raise DeletionJournalError("independent deletion journal is required")
    head = journal.head()
    if (head.journal_id, head.registry_id) != (binding.journal_id, binding.registry_id):
        raise DeletionJournalError("deletion journal binding mismatch")
    receipt = connection.execute(
        text(
            "SELECT sequence,digest FROM lucy.deletion_journal_receipts "
            "ORDER BY sequence DESC LIMIT 1"
        )
    ).one_or_none()
    acknowledged = (receipt.sequence, receipt.digest) if receipt else (0, GENESIS)
    if acknowledged != (head.sequence, head.digest):
        raise DeletionJournalError("deletion reconciliation required; storage fenced")
    return head


@lru_cache(maxsize=8)
def _local_journal(path: str, journal_id: UUID, registry_id: UUID) -> SqliteDeletionJournal:
    return SqliteDeletionJournal(Path(path), journal_id=journal_id, registry_id=registry_id)


@lru_cache(maxsize=8)
def _aws_journal(
    region: str,
    head_table: str,
    intent_table: str,
    journal_id: UUID,
    registry_id: UUID,
) -> AwsDynamoDeletionJournal:
    return AwsDynamoDeletionJournal(
        boto3.client("dynamodb", region_name=region),
        head_table=head_table,
        intent_table=intent_table,
        journal_id=journal_id,
        registry_id=registry_id,
    )


def deletion_journal_from_environment() -> DeletionJournal:
    backend = os.getenv("LUCY_ARCHIVE_BACKEND", "local-sqlite").strip()
    if backend == "aws-kms-dynamodb":
        return AwsDynamoDeletionJournal.from_environment()
    if os.getenv("LUCY_ENVIRONMENT") == "production":
        raise DeletionJournalError("production deletion journal backend is invalid")
    try:
        path = os.environ["LUCY_DELETION_JOURNAL_PATH"]
        journal_id = UUID(os.environ["LUCY_DELETION_JOURNAL_ID"])
        registry_id = UUID(os.environ["LUCY_ARCHIVE_REGISTRY_ID"])
    except (KeyError, ValueError):
        raise DeletionJournalError("independent deletion journal configuration required") from None
    return _local_journal(path, journal_id, registry_id)


def _valid_table_name(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", value) is not None


def _aws_region() -> str:
    region = os.getenv("AWS_REGION", "").strip() or os.getenv("AWS_DEFAULT_REGION", "").strip()
    if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region) is None:
        raise DeletionJournalError("AWS region is missing or invalid")
    return region


def _sequence_prefix(sequence: int) -> str:
    if not 1 <= sequence <= 9_999_999_999_999_999_999:
        raise DeletionJournalError("deletion journal sequence is invalid")
    return f"{sequence:019d}"


def _dynamo_string(item: dict[str, object], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, dict) or set(value) != {"S"} or not isinstance(value["S"], str):
        raise DeletionJournalError("deletion journal attribute is invalid")
    return value["S"]


def _dynamo_number(item: dict[str, object], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, dict) or set(value) != {"N"} or not isinstance(value["N"], str):
        raise DeletionJournalError("deletion journal attribute is invalid")
    return value["N"]


def _dynamo_binary(item: dict[str, object], name: str) -> bytes:
    value = item.get(name)
    if not isinstance(value, dict) or set(value) != {"B"}:
        raise DeletionJournalError("deletion journal attribute is invalid")
    raw = value["B"]
    if isinstance(raw, bytearray):
        return bytes(raw)
    if not isinstance(raw, bytes):
        raise DeletionJournalError("deletion journal attribute is invalid")
    return raw
