from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ezopenpn.config import SecretFiles, Settings
from ezopenpn.db import create_engine_for
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.runtime import FakeRuntimeCoordinator, RuntimeCoordinator
from ezopenpn.profiles.service import ProfileService
from ezopenpn.security.admin import AdminService
from ezopenpn.security.secrets import SecretCipher
from ezopenpn.security.sessions import SessionService
from ezopenpn.security.throttle import LoginThrottleService
from ezopenpn.web.middleware import RequestPolicyMiddleware
from ezopenpn.web.preauth import PreAuthService
from ezopenpn.web.routes import auth, health, profiles

_WEB_ROOT = Path(__file__).resolve().parent
_DEFAULT_CONFIG_PATH = Path("/etc/ezopenpn/control.toml")


@dataclass(frozen=True, slots=True)
class WebServices:
    admins: AdminService
    sessions: SessionService
    throttle: LoginThrottleService
    preauth: PreAuthService
    profiles: ProfileRepository
    runtime: RuntimeCoordinator
    expose_observed_client: bool = False


def create_app(settings: Settings, services: WebServices) -> FastAPI:
    application = FastAPI(
        title="EzOpenPN",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = settings
    application.state.services = services
    application.state.templates = Jinja2Templates(directory=_WEB_ROOT / "templates")
    application.mount(
        "/static", StaticFiles(directory=_WEB_ROOT / "static"), name="static"
    )
    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(profiles.router)
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[str(settings.public_ip), "control", "localhost", "127.0.0.1"],
    )
    application.add_middleware(
        RequestPolicyMiddleware,
        trusted_proxy_hosts=settings.trusted_proxy_hosts,
        expose_observed_client=services.expose_observed_client,
    )

    @application.exception_handler(Exception)
    async def safe_exception_handler(request: Request, error: Exception) -> PlainTextResponse:
        del request, error
        return PlainTextResponse("Внутренняя ошибка.", status_code=500)

    return application


def create_runtime_app() -> FastAPI:
    config_path = Path(os.environ.get("EZOPENPN_CONFIG_PATH", _DEFAULT_CONFIG_PATH))
    settings = Settings.load(config_path)
    secrets = SecretFiles.load(
        settings.paths.master_key_path,
        settings.paths.hysteria_api_path,
        settings.paths.hysteria_obfs_path,
    )
    engine = create_engine_for(settings.database_path)
    cipher = SecretCipher(secrets.master_key)
    profile_repository = ProfileRepository(engine, cipher)
    profile_service = ProfileService(profile_repository, cipher)
    services = WebServices(
        admins=AdminService(engine),
        sessions=SessionService(
            engine,
            secrets.master_key,
            idle_duration=timedelta(seconds=settings.session.idle_seconds),
            absolute_duration=timedelta(seconds=settings.session.absolute_seconds),
        ),
        throttle=LoginThrottleService(engine, secrets.master_key),
        preauth=PreAuthService(engine, secrets.master_key),
        profiles=profile_repository,
        runtime=FakeRuntimeCoordinator(profile_service),
    )
    return create_app(settings, services)
