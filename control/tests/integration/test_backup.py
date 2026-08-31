from __future__ import annotations

import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

from ezopenpn.backup import create_online_backup, verify_database
from ezopenpn.db import create_engine_for, upgrade_database


def _prepared_database(path: Path) -> None:
    upgrade_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO profiles (
                id, name, state, runtime_id, wrapped_profile_key,
                user_id_ciphertext, hysteria_secret_ciphertext,
                subscription_token_ciphertext
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "11111111-1111-1111-1111-111111111111",
                "Первый профиль",
                "active",
                "abcdefghijklmnopqrstuvwx1234",
                b"wrapped-profile-key",
                b"encrypted-user-id",
                b"encrypted-secondary-secret",
                b"encrypted-subscription-token",
            ),
        )
        connection.executemany(
            "INSERT INTO audit_events (id, event_type, details_json) VALUES (?, ?, ?)",
            (
                (f"event-{index:05d}", "backup.fixture", '{"safe":true}')
                for index in range(2_000)
            ),
        )


def test_online_backup_is_consistent_during_writes(tmp_path: Path) -> None:
    database = tmp_path / "source.sqlite3"
    output = tmp_path / "snapshot.sqlite3"
    _prepared_database(database)
    engine = create_engine_for(database)
    started = threading.Event()
    stop = threading.Event()

    def writer() -> None:
        with sqlite3.connect(database, timeout=5) as connection:
            connection.execute("PRAGMA busy_timeout=5000")
            index = 0
            while not stop.is_set():
                connection.execute(
                    "INSERT OR REPLACE INTO system_state (key, value_json) VALUES (?, ?)",
                    ("concurrent-write", f'{{"sequence":{index}}}'),
                )
                connection.commit()
                index += 1
                started.set()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    assert started.wait(timeout=5)
    try:
        result = create_online_backup(engine, output)
    finally:
        stop.set()
        thread.join(timeout=5)
        engine.dispose()

    verification = verify_database(result.database_path)
    assert verification.ok is True
    assert result.quick_check == "ok"
    assert result.schema_version == "0001_initial"
    assert result.sha256 == verification.sha256
    with sqlite3.connect(output) as connection:
        profile = connection.execute(
            """
            SELECT id, wrapped_profile_key, user_id_ciphertext,
                   hysteria_secret_ciphertext, subscription_token_ciphertext
            FROM profiles
            """
        ).fetchone()
    assert profile == (
        "11111111-1111-1111-1111-111111111111",
        b"wrapped-profile-key",
        b"encrypted-user-id",
        b"encrypted-secondary-secret",
        b"encrypted-subscription-token",
    )


def test_verify_database_rejects_unknown_schema(tmp_path: Path) -> None:
    database = tmp_path / "unknown.sqlite3"
    _prepared_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE alembic_version SET version_num = ?", ("future_schema",)
        )

    result = verify_database(database)

    assert result.ok is False
    assert result.schema_version == "future_schema"


def test_backup_refuses_to_replace_an_existing_file(tmp_path: Path) -> None:
    database = tmp_path / "source.sqlite3"
    output = tmp_path / "existing.sqlite3"
    _prepared_database(database)
    output.write_bytes(b"keep me")
    engine = create_engine_for(database)

    try:
        try:
            create_online_backup(engine, output)
        except FileExistsError:
            pass
        else:
            raise AssertionError("existing output must be rejected")
    finally:
        engine.dispose()

    assert output.read_bytes() == b"keep me"


def _write_config(path: Path, database: Path) -> None:
    path.write_text(
        f'[app]\npublic_ip="203.0.113.10"\ndatabase_path="{database}"\n'
        '[xray]\nreality_public_key="public-key"\n'
        'reality_server_name="www.example.org"\n'
        'reality_short_id="a1b2c3d4e5f60708"\n'
        'xhttp_path="/backup-test"\n',
        encoding="utf-8",
    )


def _run_cli(config: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ezopenpn.cli", "--config", str(config), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )


def test_backup_and_verify_cli_emit_only_safe_metadata(tmp_path: Path) -> None:
    database = tmp_path / "source.sqlite3"
    config = tmp_path / "control.toml"
    output = tmp_path / "snapshot.sqlite3"
    _prepared_database(database)
    _write_config(config, database)

    backup = _run_cli(config, "backup-database", "--output", str(output))
    verification = _run_cli(config, "verify-database", "--path", str(output))

    assert backup.returncode == 0
    assert verification.returncode == 0
    assert "0001_initial" in backup.stdout
    assert "0001_initial" in verification.stdout
    assert "encrypted-user-id" not in backup.stdout
    assert "encrypted-user-id" not in verification.stdout


def test_verify_cli_rejects_unknown_schema(tmp_path: Path) -> None:
    database = tmp_path / "unknown.sqlite3"
    config = tmp_path / "control.toml"
    _prepared_database(database)
    _write_config(config, database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE alembic_version SET version_num = ?", ("future_schema",)
        )

    result = _run_cli(config, "verify-database", "--path", str(database))

    assert result.returncode != 0
    assert "future_schema" not in result.stderr
