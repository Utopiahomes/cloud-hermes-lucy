from __future__ import annotations

from lucy.db.session import _psycopg_url


def test_standard_postgresql_url_selects_psycopg3() -> None:
    assert (
        _psycopg_url("postgresql://lucy:secret@database.internal/lucy")
        == "postgresql+psycopg://lucy:secret@database.internal/lucy"
    )


def test_explicit_database_driver_is_preserved() -> None:
    url = "postgresql+psycopg://lucy:secret@database.internal/lucy"
    assert _psycopg_url(url) == url
