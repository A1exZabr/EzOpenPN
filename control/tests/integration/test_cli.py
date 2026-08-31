from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

from sqlalchemy import select

from ezopenpn.cli import main
from ezopenpn.db import create_engine_for, session_scope
from ezopenpn.models import Admin


def _config(tmp_path: Path) -> tuple[Path, Path]:
    database = tmp_path / "state.db"
    config = tmp_path / "control.toml"
    config.write_text(
        f'[app]\npublic_ip="203.0.113.10"\ndatabase_path="{database}"\n'
        '[xray]\nreality_public_key="public-key"\n'
        'reality_server_name="www.example.org"\n'
        'reality_short_id="a1b2c3d4e5f60708"\n'
        'xhttp_path="/cli-test"\n',
        encoding="utf-8",
    )
    return config, database


def _run(
    config: Path, arguments: list[str], input_text: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ezopenpn.cli", "--config", str(config), *arguments],
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def test_init_admin_reads_password_only_from_stdin(tmp_path: Path) -> None:
    config, _ = _config(tmp_path)

    result = _run(
        config,
        ["init-admin", "--login", "owner", "--password-stdin"],
        "strong passphrase\n",
    )

    assert result.returncode == 0
    assert "strong passphrase" not in result.stdout
    assert "strong passphrase" not in result.stderr


def test_second_initial_admin_is_rejected(tmp_path: Path) -> None:
    config, _ = _config(tmp_path)
    first = _run(
        config,
        ["init-admin", "--login", "owner", "--password-stdin"],
        "first passphrase\n",
    )

    second = _run(
        config,
        ["init-admin", "--login", "other", "--password-stdin"],
        "second passphrase\n",
    )

    assert first.returncode == 0
    assert second.returncode == 4


def test_migrate_creates_a_real_database(tmp_path: Path) -> None:
    config, database = _config(tmp_path)

    result = _run(config, ["migrate"])

    assert result.returncode == 0
    assert result.stderr == ""
    assert database.is_file()


def test_reset_password_changes_the_stored_hash(tmp_path: Path) -> None:
    config, database = _config(tmp_path)
    _run(
        config,
        ["init-admin", "--login", "owner", "--password-stdin"],
        "first passphrase\n",
    )
    engine = create_engine_for(database)
    with session_scope(engine) as session:
        before = session.scalar(select(Admin))
        assert before is not None
        old_hash = before.password_hash

    result = _run(config, ["reset-password", "--password-stdin"], "second passphrase\n")

    assert result.returncode == 0
    with session_scope(engine) as session:
        after = session.scalar(select(Admin))
        assert after is not None
        assert after.password_hash != old_hash


def test_password_payload_must_be_exactly_one_line(tmp_path: Path) -> None:
    config, _ = _config(tmp_path)

    missing_newline = _run(
        config,
        ["init-admin", "--login", "owner", "--password-stdin"],
        "strong passphrase",
    )
    extra_line = _run(
        config,
        ["init-admin", "--login", "owner", "--password-stdin"],
        "strong passphrase\nextra\n",
    )

    assert missing_newline.returncode == 2
    assert extra_line.returncode == 2


def test_password_stdin_rejects_a_terminal(tmp_path: Path) -> None:
    config, _ = _config(tmp_path)

    class TerminalInput(io.StringIO):
        def isatty(self) -> bool:
            return True

    output = io.StringIO()
    error = io.StringIO()
    code = main(
        ["--config", str(config), "init-admin", "--login", "owner", "--password-stdin"],
        input_stream=TerminalInput("strong passphrase\n"),
        output_stream=output,
        error_stream=error,
    )

    assert code == 2
    assert "strong passphrase" not in output.getvalue()
    assert "strong passphrase" not in error.getvalue()
