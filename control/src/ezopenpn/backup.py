from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine

SUPPORTED_SCHEMA_VERSIONS = frozenset({"0001_initial"})
_COPY_PAGES = 128
_BUSY_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class DatabaseVerification:
    database_path: Path
    ok: bool
    quick_check: str
    schema_version: str | None
    sha256: str


@dataclass(frozen=True)
class DatabaseBackup:
    database_path: Path
    quick_check: str
    schema_version: str
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _readonly_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
        uri=True,
        timeout=_BUSY_TIMEOUT_SECONDS,
    )


def _schema_version(connection: sqlite3.Connection) -> str | None:
    rows = connection.execute("SELECT version_num FROM alembic_version").fetchall()
    if len(rows) != 1 or len(rows[0]) != 1 or not isinstance(rows[0][0], str):
        return None
    return rows[0][0]


def verify_database(path: Path) -> DatabaseVerification:
    path = path.absolute()
    digest = ""
    schema_version: str | None = None
    quick_check = "unavailable"
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise ValueError("database must be a regular file")
        digest = _sha256(path)
        with _readonly_connection(path) as connection:
            quick_rows = connection.execute("PRAGMA quick_check").fetchall()
            quick_check = "; ".join(str(row[0]) for row in quick_rows)
            schema_version = _schema_version(connection)
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchone()
    except (OSError, sqlite3.DatabaseError, ValueError):
        return DatabaseVerification(path, False, quick_check, schema_version, digest)

    return DatabaseVerification(
        database_path=path,
        ok=(
            quick_rows == [("ok",)]
            and foreign_key_errors is None
            and schema_version in SUPPORTED_SCHEMA_VERSIONS
        ),
        quick_check=quick_check,
        schema_version=schema_version,
        sha256=digest,
    )


def _engine_database_path(engine: Engine) -> Path:
    if engine.url.get_backend_name() != "sqlite" or engine.url.database is None:
        raise ValueError("only file-backed SQLite databases can be copied")
    path = Path(engine.url.database)
    if not path.is_absolute():
        raise ValueError("database path must be absolute")
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ValueError("database must be a regular file")
    return path


def _reserve_output(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("backup output path must be absolute")
    parent_status = path.parent.lstat()
    if stat.S_ISLNK(parent_status.st_mode) or not stat.S_ISDIR(parent_status.st_mode):
        raise ValueError("backup output parent must be a directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)


def create_online_backup(engine: Engine, output: Path) -> DatabaseBackup:
    source_path = _engine_database_path(engine)
    output = output.absolute()
    _reserve_output(output)
    try:
        with _readonly_connection(source_path) as source:
            source.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_SECONDS * 1_000}")
            with sqlite3.connect(output, timeout=_BUSY_TIMEOUT_SECONDS) as target:
                source.backup(target, pages=_COPY_PAGES, sleep=0.01)
        os.chmod(output, 0o600)
        verification = verify_database(output)
        if not verification.ok or verification.schema_version is None:
            raise ValueError("database backup verification failed")
        return DatabaseBackup(
            database_path=verification.database_path,
            quick_check=verification.quick_check,
            schema_version=verification.schema_version,
            sha256=verification.sha256,
        )
    except BaseException:
        output.unlink(missing_ok=True)
        raise
