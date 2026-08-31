from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import URL, Engine, create_engine, event, text
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import Session

_SOURCE_CONTROL_ROOT = Path(__file__).resolve().parents[2]


@event.listens_for(Engine, "connect")
def set_sqlite_pragmas(connection: DBAPIConnection, _: object) -> None:
    if not isinstance(connection, sqlite3.Connection):
        return
    cursor = connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA secure_delete=ON")
    finally:
        cursor.close()


def _database_url(path: Path) -> URL:
    if not path.is_absolute():
        raise ValueError("database path must be absolute")
    return URL.create("sqlite+pysqlite", database=str(path))


def create_engine_for(path: Path) -> Engine:
    return create_engine(
        _database_url(path),
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    with Session(engine) as session:
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise


def _control_root() -> Path:
    configured = os.environ.get("EZOPENPN_CONTROL_ROOT")
    root = Path(configured) if configured is not None else _SOURCE_CONTROL_ROOT
    if not root.is_absolute():
        raise ValueError("control root must be absolute")
    return root


def _alembic_config(path: Path) -> Config:
    control_root = _control_root()
    configuration = Config(str(control_root / "alembic.ini"))
    configuration.set_main_option("script_location", str(control_root / "migrations"))
    configuration.set_main_option(
        "sqlalchemy.url", _database_url(path).render_as_string(hide_password=False)
    )
    return configuration


def upgrade_database(path: Path) -> None:
    command.upgrade(_alembic_config(path), "head")


def downgrade_database(path: Path) -> None:
    command.downgrade(_alembic_config(path), "base")
    engine = create_engine_for(path)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    finally:
        engine.dispose()
