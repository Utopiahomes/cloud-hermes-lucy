"""EdDSA workload authentication and request binding for Shared Execution RC1."""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt import InvalidTokenError

AUDIENCE = "stoin:shared-model-execution"
SCOPE = "inference.execute"


class AuthenticationFailed(PermissionError):
    """The generic RC1 service-authentication failure."""


class AuthenticationStateUnavailable(RuntimeError):
    """A valid token cannot be admitted because replay state is unavailable."""


@dataclass(frozen=True)
class WorkloadIdentity:
    issuer: str
    subject: str
    realm: str
    environment: str
    keys: dict[str, Ed25519PublicKey]
    execution_profiles: frozenset[str]


class JtiReplayStore(Protocol):
    def consume(self, namespace: tuple[str, str, str, str], jti: UUID, expires_at: int) -> bool: ...


class InMemoryJtiReplayStore:
    """Content-free local replay state. Production requires a durable atomic adapter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._available = True
        self._entries: dict[tuple[str, str, str, str, UUID], int] = {}

    def set_available(self, available: bool) -> None:
        with self._lock:
            self._available = available

    def consume(
        self, namespace: tuple[str, str, str, str], jti: UUID, expires_at: int
    ) -> bool:
        with self._lock:
            if not self._available:
                raise AuthenticationStateUnavailable
            now = int(time.time())
            self._entries = {
                key: expiry for key, expiry in self._entries.items() if expiry >= now
            }
            key = (*namespace, jti)
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            return True


class WorkloadJwtVerifier:
    def __init__(self, identity: WorkloadIdentity, replay_store: JtiReplayStore) -> None:
        if not identity.keys:
            raise ValueError("at least one workload verification key is required")
        self._identity = identity
        self._replay = replay_store

    @property
    def identity(self) -> WorkloadIdentity:
        return self._identity

    def verify(
        self,
        authorization: str,
        *,
        method: str,
        path: str,
        idempotency_key: str,
        declared_body_hash: str,
        now: int | None = None,
    ) -> None:
        if not authorization.startswith("Bearer ") or authorization.count(" ") != 1:
            raise AuthenticationFailed
        token = authorization.removeprefix("Bearer ")
        observed_now = int(time.time()) if now is None else now
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "EdDSA" or set(header) - {"alg", "kid", "typ"}:
                raise AuthenticationFailed
            kid = header.get("kid")
            if not isinstance(kid, str) or kid not in self._identity.keys:
                raise AuthenticationFailed
            claims = jwt.decode(
                token,
                self._identity.keys[kid],
                algorithms=["EdDSA"],
                audience=AUDIENCE,
                issuer=self._identity.issuer,
                leeway=30,
                options={
                    "require": ["iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti", "req"]
                },
            )
            if claims.get("sub") != self._identity.subject or claims.get("scope") != SCOPE:
                raise AuthenticationFailed
            iat = _integer_claim(claims, "iat")
            nbf = _integer_claim(claims, "nbf")
            exp = _integer_claim(claims, "exp")
            if nbf > exp or exp - iat > 300 or iat > observed_now + 30:
                raise AuthenticationFailed
            jti = UUID(str(claims["jti"]), version=4)
            if str(jti) != str(claims["jti"]).lower():
                raise AuthenticationFailed
            expected = request_binding_digest(method, path, idempotency_key, declared_body_hash)
            if claims.get("req") != expected:
                raise AuthenticationFailed
        except (InvalidTokenError, KeyError, TypeError, ValueError, AuthenticationFailed):
            raise AuthenticationFailed from None

        namespace = (
            self._identity.issuer,
            self._identity.subject,
            self._identity.realm,
            self._identity.environment,
        )
        if not self._replay.consume(namespace, jti, observed_now + 600):
            raise AuthenticationFailed


def request_binding_digest(
    method: str, path: str, idempotency_key: str, declared_body_hash: str
) -> str:
    value = f"{method}\n{path}\n{idempotency_key}\n{declared_body_hash}".encode()
    return _base64url(hashlib.sha256(value).digest())


def content_sha256(body: bytes) -> str:
    return _base64url(hashlib.sha256(body).digest())


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _integer_claim(claims: dict[str, object], name: str) -> int:
    value = claims[name]
    if not isinstance(value, int) or isinstance(value, bool):
        raise AuthenticationFailed
    return value
