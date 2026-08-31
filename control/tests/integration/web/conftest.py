from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from ezopenpn.config import AppSettings, DatabaseSettings, Settings
from ezopenpn.db import create_engine_for, upgrade_database
from ezopenpn.security.admin import AdminService
from ezopenpn.security.sessions import SessionService
from ezopenpn.security.throttle import LoginThrottleService
from ezopenpn.web.app import WebServices, create_app
from ezopenpn.web.preauth import PreAuthService

MASTER_KEY = bytes(range(32))


@pytest.fixture
def web_app(tmp_path: Path):
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    admins = AdminService(engine)
    admins.create_initial("owner", "correct passphrase")
    services = WebServices(
        admins=admins,
        sessions=SessionService(engine, MASTER_KEY),
        throttle=LoginThrottleService(engine, MASTER_KEY),
        preauth=PreAuthService(engine, MASTER_KEY),
        expose_observed_client=True,
    )
    settings = Settings(
        app=AppSettings(public_ip="203.0.113.10"),
        database=DatabaseSettings(path=database),
    )
    return create_app(settings, services)


@pytest.fixture
def web_client(web_app) -> TestClient:
    with TestClient(web_app, base_url="https://203.0.113.10:9443") as client:
        yield client


def extract_csrf(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"\s]+)"', page)
    assert match is not None
    return match.group(1)
