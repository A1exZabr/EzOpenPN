from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ezopenpn.db import create_engine_for

router = APIRouter()


@router.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(request: Request) -> JSONResponse:
    engine = create_engine_for(request.app.state.settings.database_path)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            {"status": "not_ready", "code": "database_unavailable"}, status_code=503
        )
    finally:
        engine.dispose()
    runtime = request.app.state.services.runtime_health.snapshot()
    if not runtime.ready:
        return JSONResponse(
            {
                "status": "not_ready",
                "code": runtime.error_code or "runtime_reconcile_failed",
            },
            status_code=503,
        )
    return JSONResponse({"status": "ok"})
