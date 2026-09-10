from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    V13ContractVerifier,
    V13SigningKeyPurpose,
)

ROOT = Path(__file__).parents[2]


def _module() -> ModuleType:
    path = ROOT / "deploy" / "aws" / "generate_policy_identity_v1_3.py"
    spec = importlib.util.spec_from_file_location("generate_policy_identity_v1_3", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_policy_identity_has_separate_secret_and_valid_public_trust() -> None:
    now = datetime(2026, 9, 9, tzinfo=UTC)
    secret, trust = _module().generate_identity(
        key_id="utopia-policy-v13-1",
        issuer="lucy-utopia-policy",
        environment=DeploymentEnvironment.PRODUCTION,
        now=now,
    )
    assert set(secret) == {"contract", "key_id", "private_key_b64"}
    assert "private" not in trust[0].model_dump_json()
    assert trust[0].purpose == V13SigningKeyPurpose.POLICY_NOTARY
    assert trust[0].valid_from == now
    V13ContractVerifier(trust)
