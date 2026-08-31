from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO, cast

from alembic.util.exc import CommandError
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from ezopenpn.backup import create_online_backup, verify_database
from ezopenpn.config import Settings
from ezopenpn.db import create_engine_for, upgrade_database
from ezopenpn.security.admin import (
    AdminAlreadyExists,
    AdminNotInitialized,
    AdminService,
    InvalidAdminInput,
)

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_DATABASE_UNAVAILABLE = 3
EXIT_STATE_CONFLICT = 4
EXIT_MIGRATION_FAILED = 5
EXIT_BACKUP_FAILED = 6
_DEFAULT_CONFIG = Path("/etc/ezopenpn/control.toml")
_MAX_PASSWORD_LENGTH = 1024


class PasswordInputError(ValueError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ezopenpn-control")
    parser.add_argument("--config", type=Path, default=_DEFAULT_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init-admin")
    initialize.add_argument("--login", required=True)
    initialize.add_argument("--password-stdin", action="store_true", required=True)

    reset = commands.add_parser("reset-password")
    reset.add_argument("--password-stdin", action="store_true", required=True)

    commands.add_parser("migrate")
    backup = commands.add_parser("backup-database")
    backup.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify-database")
    verify.add_argument("--path", type=Path, required=True)
    return parser


def _read_password(stream: IO[str]) -> str:
    if stream.isatty():
        raise PasswordInputError("terminal input is not accepted")
    payload = stream.read(_MAX_PASSWORD_LENGTH + 2)
    if len(payload) > _MAX_PASSWORD_LENGTH + 1:
        raise PasswordInputError("password input is too long")
    if not payload.endswith("\n") or payload.count("\n") != 1 or "\r" in payload:
        raise PasswordInputError("password input must be exactly one line")
    return payload[:-1]


def _load_settings(config_path: Path, error_stream: IO[str]) -> Settings | None:
    try:
        return Settings.load(config_path)
    except (OSError, ValueError):
        print("Настройки не удалось прочитать.", file=error_stream)
        return None


def _migrate(database_path: Path, error_stream: IO[str]) -> int:
    try:
        upgrade_database(database_path)
    except OperationalError:
        print("Хранилище недоступно.", file=error_stream)
        return EXIT_DATABASE_UNAVAILABLE
    except (CommandError, SQLAlchemyError, OSError, ValueError):
        print("Обновление хранилища не выполнено.", file=error_stream)
        return EXIT_MIGRATION_FAILED
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    input_stream: IO[str] | None = None,
    output_stream: IO[str] | None = None,
    error_stream: IO[str] | None = None,
) -> int:
    input_stream = input_stream or sys.stdin
    output_stream = output_stream or sys.stdout
    error_stream = error_stream or sys.stderr
    arguments = _parser().parse_args(argv)
    config_path = cast(Path, arguments.config)
    command_name = cast(str, arguments.command)
    settings = _load_settings(config_path, error_stream)
    if settings is None:
        return EXIT_INVALID_INPUT

    if command_name == "verify-database":
        verification = verify_database(cast(Path, arguments.path))
        if not verification.ok or verification.schema_version is None:
            print("Резервная копия хранилища не прошла проверку.", file=error_stream)
            return EXIT_STATE_CONFLICT
        print(
            json.dumps(
                {
                    "quick_check": verification.quick_check,
                    "schema_version": verification.schema_version,
                    "sha256": verification.sha256,
                },
                sort_keys=True,
            ),
            file=output_stream,
        )
        return EXIT_OK

    if command_name == "backup-database":
        engine = create_engine_for(settings.database_path)
        try:
            backup_result = create_online_backup(engine, cast(Path, arguments.output))
        except (OSError, SQLAlchemyError, ValueError):
            print("Резервную копию хранилища создать не удалось.", file=error_stream)
            return EXIT_BACKUP_FAILED
        finally:
            engine.dispose()
        print(
            json.dumps(
                {
                    "quick_check": backup_result.quick_check,
                    "schema_version": backup_result.schema_version,
                    "sha256": backup_result.sha256,
                },
                sort_keys=True,
            ),
            file=output_stream,
        )
        return EXIT_OK

    migration_status = _migrate(settings.database_path, error_stream)
    if migration_status != EXIT_OK:
        return migration_status
    if command_name == "migrate":
        print("Хранилище готово.", file=output_stream)
        return EXIT_OK

    try:
        password = _read_password(input_stream)
    except PasswordInputError:
        print("Пароль нужно передать одной строкой через stdin.", file=error_stream)
        return EXIT_INVALID_INPUT

    service = AdminService(create_engine_for(settings.database_path))
    try:
        if command_name == "init-admin":
            service.create_initial(cast(str, arguments.login), password)
            print("Администратор создан.", file=output_stream)
        elif command_name == "reset-password":
            service.reset_password(password)
            print("Пароль обновлён. Все сеансы завершены.", file=output_stream)
        else:
            print("Неизвестная команда.", file=error_stream)
            return EXIT_INVALID_INPUT
    except InvalidAdminInput:
        print("Проверьте введённые данные.", file=error_stream)
        return EXIT_INVALID_INPUT
    except (AdminAlreadyExists, AdminNotInitialized):
        print("Команда не подходит для текущего состояния.", file=error_stream)
        return EXIT_STATE_CONFLICT
    except OperationalError:
        print("Хранилище недоступно.", file=error_stream)
        return EXIT_DATABASE_UNAVAILABLE
    finally:
        del password

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
