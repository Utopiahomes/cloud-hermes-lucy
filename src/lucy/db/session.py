from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def _psycopg_url(database_url: str) -> str:
    """Select the installed Psycopg 3 driver for standard PostgreSQL URLs."""
    if database_url.startswith("postgresql://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgresql://')}"
    return database_url


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    engine: Engine = create_engine(_psycopg_url(database_url), pool_pre_ping=True)
    return sessionmaker(engine, expire_on_commit=False)
