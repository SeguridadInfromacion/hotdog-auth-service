"""Rutas HTTP. Solo traducen entre HTTP y los casos de uso."""

import uuid
from contextlib import suppress
from datetime import timedelta

from fastapi import APIRouter, Request, Response, status

from app.config import Settings
from app.database import utcnow
from app.dependencies import (
    SESSION_COOKIE,
    AdminUser,
    ClientIp,
    CurrentUser,
    SessionDep,
    SettingsDep,
    extract_token,
)
from app.errors import NotAuthenticated
from app.repositories import AuditRepository
from app.schemas import AuditOut, LoginIn, SessionOut, UserCreate, UserOut, UserUpdate
from app.security import decode_token, issue_token
from app.services import AuthService, UserService

COOKIE_PATH = "/api"

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"])


def _set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    # El token viaja en una cookie HttpOnly: el JavaScript de la página no puede
    # leerlo, así que un XSS no puede robar la sesión.
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=settings.access_token_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path=COOKIE_PATH,
    )


@auth_router.post("/login", response_model=SessionOut)
def login(
    credentials: LoginIn,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    ip: ClientIp,
) -> SessionOut:
    user = AuthService(session, settings).authenticate(
        credentials.username, credentials.password, ip
    )
    token, expires_at = issue_token(user)
    _set_session_cookie(response, token, settings)
    return SessionOut(user=UserOut.model_validate(user), expires_at=expires_at)


@auth_router.post("/refresh", response_model=SessionOut)
def refresh(
    request: Request, response: Response, user: CurrentUser, settings: SettingsDep
) -> SessionOut:
    """Cambia un token vigente por uno nuevo. CurrentUser ya comprobó en la base
    que el usuario sigue activo y que el token no fue invalidado."""
    claims = decode_token(extract_token(request) or "")
    session_limit = claims.session_started_at + timedelta(hours=settings.session_hours)
    if utcnow() >= session_limit:
        raise NotAuthenticated("Tu sesión cumplió el tiempo máximo. Entra de nuevo.")
    token, expires_at = issue_token(user, claims.session_started_at)
    _set_session_cookie(response, token, settings)
    return SessionOut(user=UserOut.model_validate(user), expires_at=expires_at)


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request, response: Response, session: SessionDep, settings: SettingsDep, ip: ClientIp
) -> None:
    token = extract_token(request)
    if token is not None:
        # Un token inválido o vencido no tiene nada que cerrar: solo se borra la cookie.
        with suppress(NotAuthenticated):
            AuthService(session, settings).end_session(decode_token(token), ip)
    response.delete_cookie(
        key=SESSION_COOKIE,
        path=COOKIE_PATH,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


@auth_router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)


@auth_router.get("/audit", response_model=list[AuditOut])
def audit_trail(_: AdminUser, session: SessionDep) -> list[AuditOut]:
    return [AuditOut.model_validate(entry) for entry in AuditRepository(session).recent()]


@users_router.get("", response_model=list[UserOut])
def list_users(_: AdminUser, session: SessionDep) -> list[UserOut]:
    return [UserOut.model_validate(user) for user in UserService(session).list_users()]


@users_router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(data: UserCreate, admin: AdminUser, session: SessionDep, ip: ClientIp) -> UserOut:
    user = UserService(session).create_user(data, actor=admin.username, ip=ip)
    return UserOut.model_validate(user)


@users_router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID, data: UserUpdate, admin: AdminUser, session: SessionDep, ip: ClientIp
) -> UserOut:
    user = UserService(session).update_user(user_id, data, actor=admin, ip=ip)
    return UserOut.model_validate(user)
