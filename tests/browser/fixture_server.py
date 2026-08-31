from __future__ import annotations

import argparse
import tempfile
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response
from sqlalchemy import delete

from ezopenpn.config import AppSettings, DatabaseSettings, Settings, XraySettings
from ezopenpn.db import create_engine_for, session_scope, upgrade_database
from ezopenpn.models import AdminSession, AuditEvent, LoginThrottle, Profile, SystemState
from ezopenpn.profiles.coordinator import ProfileCoordinator
from ezopenpn.profiles.links import ProfileLinkService, TransportLinkConfig
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.service import ProfileService
from ezopenpn.security.admin import AdminService
from ezopenpn.security.secrets import SecretCipher
from ezopenpn.security.sessions import SessionService
from ezopenpn.security.throttle import LoginThrottleService
from ezopenpn.web.app import WebServices, create_app
from ezopenpn.web.dependencies import authenticated_browser
from ezopenpn.web.preauth import PreAuthService

_MASTER_KEY = bytes(range(32))
_ADMIN_LOGIN = "owner"
_ADMIN_PASSPHRASE = "browser fixture phrase"


class FixtureXray:
    def __init__(self) -> None:
        self.users: dict[str, object] = {}

    def add_user(self, runtime_id: str, user_id: object) -> None:
        self.users[runtime_id] = user_id

    def remove_user(self, runtime_id: str) -> None:
        self.users.pop(runtime_id, None)

    def list_users(self) -> set[str]:
        return set(self.users)

    def wait_ready(self, timeout_seconds: float) -> None:
        if timeout_seconds != 6.0:
            raise ValueError("unexpected readiness timeout")


class FixtureHysteria:
    def kick(self, runtime_id: str) -> None:
        del runtime_id


class FixtureSupervisor:
    def __init__(self, xray: FixtureXray) -> None:
        self._xray = xray

    def restart(self) -> None:
        self._xray.users.clear()


def _create_fixture_app(root: Path) -> FastAPI:
    database = root / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    admins = AdminService(engine)
    admins.create_initial(_ADMIN_LOGIN, _ADMIN_PASSPHRASE)
    cipher = SecretCipher(_MASTER_KEY)
    profiles = ProfileRepository(engine, cipher)
    settings = Settings(
        app=AppSettings(public_ip=IPv4Address("203.0.113.10")),
        database=DatabaseSettings(path=database),
        xray=XraySettings(
            reality_public_key="fixture-public-key",
            reality_server_name="www.example.org",
            reality_short_id="a1b2c3d4e5f60708",
            xhttp_path="/browser-fixture",
        ),
    )
    links = ProfileLinkService(
        profiles,
        cipher,
        TransportLinkConfig(
            host=settings.public_ip,
            reality_public_key=settings.xray.reality_public_key,
            reality_server_name=settings.xray.reality_server_name,
            reality_short_id=settings.xray.reality_short_id,
            xhttp_path=settings.xray.xhttp_path,
            hysteria_obfs_password="fixture-obfs-value",
        ),
    )
    xray = FixtureXray()
    services = WebServices(
        admins=admins,
        sessions=SessionService(engine, _MASTER_KEY),
        throttle=LoginThrottleService(engine, _MASTER_KEY),
        preauth=PreAuthService(engine, _MASTER_KEY),
        profiles=profiles,
        runtime=ProfileCoordinator(
            profiles,
            cipher,
            links,
            xray,
            FixtureHysteria(),
            FixtureSupervisor(xray),
            profile_service=ProfileService(profiles, cipher),
        ),
        links=links,
    )
    application = create_app(settings, services)

    @application.post("/__fixture__/reset", include_in_schema=False)
    def reset_fixture() -> Response:
        with session_scope(engine) as session:
            session.execute(delete(AdminSession))
            session.execute(delete(LoginThrottle))
            session.execute(delete(SystemState))
            session.execute(delete(AuditEvent))
            session.execute(delete(Profile))
        xray.users.clear()
        return Response(status_code=204)

    @application.post("/__fixture__/expire-session", include_in_schema=False)
    def expire_session(request: Request) -> Response:
        browser = authenticated_browser(request)
        if browser is None:
            return Response(status_code=401)
        with session_scope(engine) as session:
            stored = session.get(AdminSession, str(browser.identity.session_id))
            if stored is None:
                return Response(status_code=404)
            stored.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        return Response(status_code=204)

    return application


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the isolated browser fixture")
    parser.add_argument("--port", type=int, default=9444)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ezopenpn-browser-") as temporary:
        root = Path(temporary)
        uvicorn.run(
            _create_fixture_app(root),
            host="127.0.0.1",
            port=arguments.port,
            access_log=False,
            log_level="warning",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
