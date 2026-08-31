from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ezopenpn.config import Settings
from ezopenpn.security.admin import AdminService
from ezopenpn.security.sessions import SessionService
from ezopenpn.security.throttle import LoginThrottleService
from ezopenpn.web.middleware import RequestPolicyMiddleware
from ezopenpn.web.preauth import PreAuthService
from ezopenpn.web.routes import auth, health

_WEB_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True, slots=True)
class WebServices:
    admins: AdminService
    sessions: SessionService
    throttle: LoginThrottleService
    preauth: PreAuthService
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
