"""Pure transition policy; persistence is implemented by the control store."""

from lucy.contracts import RejoiningState

_ALLOWED: dict[RejoiningState, frozenset[RejoiningState]] = {
    RejoiningState.OFFLINE: frozenset({RejoiningState.REJOINING}),
    RejoiningState.REJOINING: frozenset(
        {RejoiningState.RECONCILING, RejoiningState.DEGRADED}
    ),
    RejoiningState.RECONCILING: frozenset({RejoiningState.READY, RejoiningState.DEGRADED}),
    RejoiningState.READY: frozenset({RejoiningState.OFFLINE, RejoiningState.DEGRADED}),
    RejoiningState.DEGRADED: frozenset({RejoiningState.REJOINING, RejoiningState.OFFLINE}),
}


def can_transition(current: RejoiningState, target: RejoiningState) -> bool:
    """Return whether the explicit lifecycle transition is permitted."""

    return target in _ALLOWED[current]

