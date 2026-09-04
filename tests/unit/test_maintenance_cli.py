from __future__ import annotations

from unittest.mock import patch

from lucy.authorization import SensitiveActionPermitVerifier
from lucy.maintenance import _permit_verifier_for_recovery


def test_prepare_without_deletion_recovery_does_not_load_legacy_permit_trust() -> None:
    with patch.object(
        SensitiveActionPermitVerifier,
        "from_environment",
        side_effect=AssertionError("legacy permit trust must not be loaded"),
    ) as from_environment:
        assert _permit_verifier_for_recovery(recover_deletions=False) is None
    from_environment.assert_not_called()


def test_deletion_recovery_still_requires_legacy_permit_trust() -> None:
    verifier = object()
    with patch.object(
        SensitiveActionPermitVerifier,
        "from_environment",
        return_value=verifier,
    ) as from_environment:
        assert _permit_verifier_for_recovery(recover_deletions=True) is verifier
    from_environment.assert_called_once_with()
