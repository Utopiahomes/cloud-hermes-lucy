from lucy.contracts import RejoiningState
from lucy.rejoining import can_transition


def test_happy_path_requires_reconciliation_before_ready() -> None:
    assert can_transition(RejoiningState.OFFLINE, RejoiningState.REJOINING)
    assert can_transition(RejoiningState.REJOINING, RejoiningState.RECONCILING)
    assert can_transition(RejoiningState.RECONCILING, RejoiningState.READY)
    assert not can_transition(RejoiningState.REJOINING, RejoiningState.READY)


def test_ambiguous_recovery_can_degrade() -> None:
    assert can_transition(RejoiningState.REJOINING, RejoiningState.DEGRADED)
    assert can_transition(RejoiningState.RECONCILING, RejoiningState.DEGRADED)

