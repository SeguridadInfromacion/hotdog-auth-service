"""Casos de uso: inicio de sesión y administración de usuarios."""

import re
import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import utcnow
from app.errors import AppError, Conflict, InvalidCredentials, NotFound, PermissionDenied
from app.models import ROLE_ADMIN, ROLE_CASHIER, LoginThrottle, User
from app.repositories import AuditRepository, LoginThrottleRepository, UserRepository
from app.schemas import USERNAME_PATTERN, UserCreate, UserUpdate
from app.security import DUMMY_HASH, TokenClaims, hash_password, verify_password

UNKNOWN_ACTOR = "desconocido"
# Cambiar cualquiera de estos campos cierra las sesiones abiertas del usuario.
SESSION_ENDING_FIELDS = frozenset({"password", "role", "is_active"})


class AuthService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._users = UserRepository(session)
        self._throttles = LoginThrottleRepository(session)
        self._audit = AuditRepository(session)

    def authenticate(self, username: str, password: str, ip: str) -> User:
        """Devuelve el usuario si las credenciales son correctas; si no, InvalidCredentials."""
        username = username.lower()
        now = utcnow()
        user = self._users.get_by_username(username)
        throttle = self._throttles.get_locked(username, ip) if user else None

        is_locked = throttle is not None and throttle.is_locked(now)
        if user is None or not user.is_active or is_locked:
            verify_password(DUMMY_HASH, password)  # iguala el tiempo de respuesta
            self._reject(username, ip)

        if not verify_password(user.password_hash, password):
            self._register_failure(user.username, ip, throttle, now)
            self._reject(username, ip)

        if throttle is not None:
            self._throttles.delete(throttle)
        self._audit.record(actor=user.username, action="login.ok", ip=ip)
        self._session.commit()
        return user

    def end_session(self, claims: TokenClaims, ip: str) -> None:
        """Cierra la sesión: el token deja de valer aunque alguien lo haya copiado."""
        user = self._users.get(claims.user_id)
        if user is None or user.token_version != claims.token_version:
            return
        user.token_version += 1
        self._audit.record(actor=user.username, action="logout", ip=ip)
        self._session.commit()

    def _register_failure(
        self, username: str, ip: str, throttle: LoginThrottle | None, now: datetime
    ) -> None:
        window = timedelta(minutes=self._settings.lockout_minutes)
        if throttle is None:
            throttle = self._throttles.start(username, ip)
        if now - throttle.first_failure_at > window:
            # Los fallos viejos caducan: no se acumulan durante meses.
            throttle.failed_attempts = 0
            throttle.first_failure_at = now
        throttle.failed_attempts += 1
        if throttle.failed_attempts >= self._settings.max_failed_logins:
            throttle.failed_attempts = 0
            throttle.first_failure_at = now
            throttle.locked_until = now + window
            self._audit.record(actor=username, action="login.bloqueo", target=username, ip=ip)

    def _reject(self, attempted_username: str, ip: str) -> None:
        # Solo se registra el nombre si tiene forma de usuario: a veces la gente
        # escribe la contraseña en el campo equivocado y no debe quedar guardada.
        is_username = re.fullmatch(USERNAME_PATTERN, attempted_username) is not None
        actor = attempted_username if is_username else UNKNOWN_ACTOR
        self._audit.record(actor=actor, action="login.fallido", ip=ip)
        self._session.commit()
        raise InvalidCredentials


class UserService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._users = UserRepository(session)
        self._throttles = LoginThrottleRepository(session)
        self._audit = AuditRepository(session)

    def list_users(self) -> Sequence[User]:
        return self._users.list_all()

    def create_user(self, data: UserCreate, *, actor: str, ip: str = "") -> User:
        user = User(
            username=data.username,
            full_name=data.full_name,
            password_hash=hash_password(data.password),
            role=data.role,
        )
        try:
            self._users.add(user)
        except IntegrityError as error:
            self._session.rollback()
            raise Conflict("Ya existe un usuario con ese nombre.") from error
        self._audit.record(actor=actor, action="usuario.crear", target=user.username, ip=ip)
        self._session.commit()
        return user

    def update_user(self, user_id: uuid.UUID, data: UserUpdate, *, actor: User, ip: str) -> User:
        user = self._users.get(user_id)
        if user is None:
            raise NotFound("Ese usuario no existe.")

        changes = data.model_dump(exclude_unset=True, exclude_none=True)
        if not changes:
            raise AppError("No hay cambios para guardar.")
        self._forbid_self_lockout(user, actor, changes)

        changed_fields = sorted(changes)
        new_password = changes.pop("password", None)
        if new_password is not None:
            user.password_hash = hash_password(new_password)
            self._throttles.clear_for(user.username)
        for field, value in changes.items():
            setattr(user, field, value)
        if SESSION_ENDING_FIELDS.intersection(changed_fields):
            user.token_version += 1

        self._audit.record(
            actor=actor.username,
            action="usuario.editar",
            target=f"{user.username}: {', '.join(changed_fields)}",
            ip=ip,
        )
        self._session.commit()
        return user

    @staticmethod
    def _forbid_self_lockout(user: User, actor: User, changes: dict) -> None:
        """Evita que el sistema se quede sin administrador por accidente."""
        if user.id != actor.id:
            return
        if changes.get("is_active") is False or changes.get("role", ROLE_ADMIN) != ROLE_ADMIN:
            raise PermissionDenied("No puedes desactivarte ni quitarte el rol de administrador.")

    def ensure_initial_users(
        self,
        admin: tuple[str | None, str | None],
        demo_cashier: tuple[str | None, str | None],
    ) -> None:
        """Crea los usuarios iniciales solo si todavía no hay ninguno."""
        if self._users.count() > 0:
            return
        if not all(admin):
            # Sin administrador nadie podría crear usuarios: mejor no arrancar.
            raise RuntimeError(
                "La base de usuarios está vacía: define ADMIN_USERNAME y ADMIN_PASSWORD."
            )
        initial = [
            (admin, ROLE_ADMIN, "Administrador"),
            (demo_cashier, ROLE_CASHIER, "Cajero de turno"),
        ]
        for (username, password), role, full_name in initial:
            if not username or not password:
                continue
            data = UserCreate(username=username, full_name=full_name, password=password, role=role)
            self.create_user(data, actor="sistema")
