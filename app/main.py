"""Punto de entrada del servicio de autenticación."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import session_scope
from app.dependencies import require_csrf_header
from app.errors import AppError
from app.routes import auth_router, users_router
from app.services import UserService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("auth-service")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    with session_scope() as session:
        UserService(session).ensure_initial_users(
            admin=(settings.admin_username, settings.admin_password),
            demo_cashier=(settings.demo_cashier_username, settings.demo_cashier_password),
        )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="hotdog-auth-service",
        lifespan=lifespan,
        dependencies=[Depends(require_csrf_header)],
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.include_router(auth_router)
    app.include_router(users_router)

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.middleware("http")
    async def never_cache_api_responses(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(AppError)
    async def handle_app_error(_: Request, error: AppError) -> JSONResponse:
        return JSONResponse(status_code=error.status_code, content={"detail": error.detail})

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, error: Exception) -> JSONResponse:
        # El detalle va al log del servidor; al cliente nunca se le muestran trazas.
        logger.exception("Error no controlado", exc_info=error)
        return JSONResponse(status_code=500, content={"detail": "Ocurrió un error interno."})

    return app
