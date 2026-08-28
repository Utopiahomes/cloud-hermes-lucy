from lucy.openrouter_eval import (
    CASES,
    PER_REQUEST_RESERVATION_MICROUSD,
    TOTAL_CAP_MICROUSD,
)


def test_evaluation_reservations_stay_below_total_cap() -> None:
    assert len(CASES) * PER_REQUEST_RESERVATION_MICROUSD <= TOTAL_CAP_MICROUSD
    assert all("synthetic" not in case.prompt.lower() for case in CASES)
