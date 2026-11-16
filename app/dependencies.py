"""Dependencias de FastAPI: sesión, usuario actual, roles y protección CSRF."""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_session
from app.errors import NotAuthenticated, PermissionDenied
from app.models import ROLE_ADMIN, User
from app.repositories import UserRepository
from app.security import decode_token

SESSION_COOKIE = "access_token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


ClientIp = Annotated[str, Depends(client_ip)]


def require_csrf_header(request: Request) -> None:
    """Defensa anti-CSRF: toda petición que modifica datos debe traer una cabecera
    que un formulario de otro sitio no puede enviar (complementa SameSite=Strict)."""
    if request.method in SAFE_METHODS:
        return
    if request.headers.get("x-requested-with") != "XMLHttpRequest":
        raise PermissionDenied("Petición rechazada: falta la cabecera de seguridad.")


def _extract_token(request: Request) -> str | None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        return cookie
    scheme, _, credentials = request.headers.get("authorization", "").partition(" ")
    return credentials if scheme.lower() == "bearer" and credentials else None


def get_current_user(request: Request, session: SessionDep) -> User:
    token = _extract_token(request)
    if token is None:
        raise NotAuthenticated
    claims = decode_token(token)
    # Aquí sí se consulta la base: un usuario desactivado deja de entrar de inmediato.
    user = UserRepository(session).get(claims.user_id)
    if user is None or not user.is_active:
        raise NotAuthenticated
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != ROLE_ADMIN:
        raise PermissionDenied
    return user


AdminUser = Annotated[User, Depends(require_admin)]
