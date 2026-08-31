from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine, select

from ezopenpn.db import create_engine_for, session_scope, upgrade_database
from ezopenpn.models import Admin
from ezopenpn.security.admin import AdminAlreadyExists, AdminService, InvalidAdminInput


def _engine(tmp_path: Path) -> Engine:
    database = tmp_path / "state.db"
    upgrade_database(database)
    return create_engine_for(database)


def test_initial_admin_normalizes_login_and_rejects_a_second_admin(tmp_path: Path) -> None:
    service = AdminService(_engine(tmp_path))

    created = service.create_initial("  OwＮer  ", "first strong password")

    assert created.login == "owner"
    with pytest.raises(AdminAlreadyExists):
        service.create_initial("other", "second strong password")


@pytest.mark.parametrize(
    ("login", "phrase"),
    [
        ("", "first strong password"),
        ("owner", "too short"),
        ("owner", "owner"),
        ("owner\nroot", "first strong password"),
    ],
)
def test_initial_admin_rejects_unsafe_input(tmp_path: Path, login: str, phrase: str) -> None:
    service = AdminService(_engine(tmp_path))

    with pytest.raises(InvalidAdminInput):
        service.create_initial(login, phrase)


def test_unknown_login_and_wrong_password_have_the_same_result(tmp_path: Path) -> None:
    service = AdminService(_engine(tmp_path))
    service.create_initial("owner", "first strong password")
    now = datetime(2026, 8, 31, 10, 0, tzinfo=UTC)

    unknown = service.verify_credentials("missing", "first strong password", now)
    incorrect = service.verify_credentials("owner", "wrong strong password", now)

    assert unknown is None
    assert incorrect is None


def test_successful_login_updates_last_login_time(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    service = AdminService(engine)
    service.create_initial("owner", "first strong password")
    now = datetime(2026, 8, 31, 10, 0, tzinfo=UTC)

    verified = service.verify_credentials("OWNER", "first strong password", now)

    assert verified is not None
    with session_scope(engine) as session:
        stored = session.scalar(select(Admin))
        assert stored is not None
        assert stored.last_login_at == now
