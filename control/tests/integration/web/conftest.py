from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from ezopenpn.config import AppSettings, DatabaseSettings, Settings, XraySettings
from ezopenpn.db import create_engine_for, upgrade_database
from ezopenpn.profiles.links import ProfileLinkService, TransportLinkConfig
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.runtime import FakeRuntimeCoordinator
from ezopenpn.profiles.service import ProfileService
from ezopenpn.security.admin import AdminService
from ezopenpn.security.secrets import SecretCipher
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
    cipher = SecretCipher(MASTER_KEY)
    profiles = ProfileRepository(engine, cipher)
    settings = Settings(
        app=AppSettings(public_ip="203.0.113.10"),
        database=DatabaseSettings(path=database),
        xray=XraySettings(
            reality_public_key="public-key",
            reality_server_name="www.example.org",
            reality_short_id="a1b2c3d4e5f60708",
            xhttp_path="/panel-test",
        ),
    )
    services = WebServices(
        admins=admins,
        sessions=SessionService(engine, MASTER_KEY),
        throttle=LoginThrottleService(engine, MASTER_KEY),
        preauth=PreAuthService(engine, MASTER_KEY),
        profiles=profiles,
        runtime=FakeRuntimeCoordinator(ProfileService(profiles, cipher)),
        links=ProfileLinkService(
            profiles,
            cipher,
            TransportLinkConfig(
                host=settings.public_ip,
                reality_public_key=settings.xray.reality_public_key,
                reality_server_name=settings.xray.reality_server_name,
                reality_short_id=settings.xray.reality_short_id,
                xhttp_path=settings.xray.xhttp_path,
                hysteria_obfs_password="obfs-secret",
            ),
        ),
        expose_observed_client=True,
    )
    return create_app(settings, services)


@pytest.fixture
def web_client(web_app) -> TestClient:
    with TestClient(web_app, base_url="https://203.0.113.10:9443") as client:
        yield client


@pytest.fixture
def authenticated_client(web_app) -> TestClient:
    with TestClient(web_app, base_url="https://203.0.113.10:9443") as client:
        csrf = extract_csrf(client.get("/login").text)
        response = client.post(
            "/login",
            data={"login": "owner", "password": "correct passphrase", "csrf": csrf},
            follow_redirects=False,
        )
        assert response.status_code == 303
        yield client


def extract_csrf(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"\s]+)"', page)
    assert match is not None
    return match.group(1)
