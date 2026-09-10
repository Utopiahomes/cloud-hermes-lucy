from __future__ import annotations

from lucy.db.session import _psycopg_url
from lucy.readiness import admitted_session_factory


def test_standard_postgresql_url_selects_psycopg3() -> None:
    assert (
        _psycopg_url("postgresql://lucy:secret@database.internal/lucy")
        == "postgresql+psycopg://lucy:secret@database.internal/lucy"
    )


def test_explicit_database_driver_is_preserved() -> None:
    url = "postgresql+psycopg://lucy:secret@database.internal/lucy"
    assert _psycopg_url(url) == url


def test_admitted_session_uses_psycopg3_for_standard_render_url() -> None:
    admitted_session_factory.cache_clear()
    sessions = admitted_session_factory(
        "postgresql://lucy:secret@database.internal/lucy", None
    )
    assert sessions.kw["bind"].url.drivername == "postgresql+psycopg"
    sessions.kw["bind"].dispose()
    admitted_session_factory.cache_clear()
