from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    engine: Engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(engine, expire_on_commit=False)

