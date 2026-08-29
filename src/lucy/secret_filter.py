"""High-confidence credential rejection before plaintext memory promotion."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretFinding:
    category: str


class MemorySecretDetected(ValueError):
    """Raised without retaining or echoing the candidate secret."""

    def __init__(self, categories: tuple[str, ...]) -> None:
        self.categories = categories
        super().__init__("credential-like content cannot be promoted to normal memory")


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.IGNORECASE),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "github_token",
        re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    ),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    (
        "telegram_bot_token",
        re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"),
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}\b", re.IGNORECASE),
    ),
    (
        "labelled_secret",
        re.compile(
            r"\b(?:password|passwd|passphrase|api[ _-]?key|secret|access[ _-]?token|"
            r"refresh[ _-]?token|recovery[ _-]?code)\b\s*(?:is|=|:)\s*\S{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "seed_phrase",
        re.compile(
            r"\b(?:seed|recovery|mnemonic)\s+phrase\b\s*(?:is|=|:)\s*"
            r"(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}\b",
            re.IGNORECASE,
        ),
    ),
)


def detect_memory_secrets(*values: str) -> tuple[SecretFinding, ...]:
    text = "\n".join(values)
    return tuple(
        SecretFinding(category)
        for category, pattern in _PATTERNS
        if pattern.search(text) is not None
    )


def reject_memory_secrets(*values: str) -> None:
    findings = detect_memory_secrets(*values)
    if findings:
        raise MemorySecretDetected(tuple(finding.category for finding in findings))
