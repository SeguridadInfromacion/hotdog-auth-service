"""Casos de uso: inicio de sesión y administración de usuarios."""

import re
import uuid
from collections.abc import Sequence
from datetime import timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import utcnow
from app.errors import Conflict, InvalidCredentials, NotFound, PermissionDenied
from app.models import ROLE_ADMIN, ROLE_CASHIER, User
from app.repositories import AuditRepository, UserRepository
from app.schemas import USERNAME_PATTERN, UserCreate, UserUpdate, validate_password_strength
from app.security import DUMMY_HASH, hash_password, verify_password

UNKNOWN_ACTOR = "desconocido"


class AuthService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._users = UserRepository(session)
        self._audit = AuditRepository(session)

    def authenticate(self, username: str, password: str, ip: str) -> User:
        """Devuelve el usuario si las credenciales son correctas; si no, InvalidCredentials."""
        username = username.lower()
        user = self._users.get_by_username(username)

        if user is None or not user.is_active or self._is_locked(user):
            verify_password(DUMMY_HASH, password)  # iguala el tiempo de respuesta
            self._reject(username, ip)

        if not verify_password(user.password_hash, password):
            self._register_failure(user)
            self._reject(username, ip)

        user.failed_attempts = 0
        user.locked_until = None
        self._audit.record(actor=user.username, action="login.ok", ip=ip)
        self._session.commit()
        return user

    @staticmethod
    def _is_locked(user: User) -> bool:
        return user.locked_until is not None and user.locked_until > utcnow()

    def _register_failure(self, user: User) -> None:
        user.failed_attempts += 1
        if user.failed_attempts >= self._settings.max_failed_logins:
            user.failed_attempts = 0
            user.locked_until = utcnow() + timedelta(minutes=self._settings.lockout_minutes)
            self._audit.record(actor=user.username, action="login.bloqueo", target=user.username)

    def _reject(self, attempted_username: str, ip: str) -> None:
        # Solo se registra el nombre si tiene forma de usuario: a veces la gente
        # escribe la contraseña en el campo equivocado y no debe quedar guardada.
        actor = (
            attempted_username if re.match(USERNAME_PATTERN, attempted_username) else UNKNOWN_ACTOR
        )
        self._audit.record(actor=actor, action="login.fallido", ip=ip)
        self._session.commit()
        raise InvalidCredentials


class UserService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._users = UserRepository(session)
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
        is_self = user.id == actor.id
        if is_self and (
            changes.get("is_active") is False or changes.get("role", ROLE_ADMIN) != ROLE_ADMIN
        ):
            # Evita que el sistema se quede sin administrador por accidente.
            raise PermissionDenied("No puedes desactivarte ni quitarte el rol de administrador.")

        new_password = changes.pop("password", None)
        if new_password is not None:
            user.password_hash = hash_password(new_password)
            user.failed_attempts = 0
            user.locked_until = None
        for field, value in changes.items():
            setattr(user, field, value)

        changed_fields = sorted([*changes, *(["password"] if new_password else [])])
        self._audit.record(
            actor=actor.username,
            action="usuario.editar",
            target=f"{user.username}: {', '.join(changed_fields)}",
            ip=ip,
        )
        self._session.commit()
        return user

    def ensure_initial_users(
        self,
        admin: tuple[str | None, str | None],
        demo_cashier: tuple[str | None, str | None],
    ) -> None:
        """Crea los usuarios iniciales solo si todavía no hay ninguno."""
        if self._users.count() > 0:
            return
        initial = [
            (admin, ROLE_ADMIN, "Administrador"),
            (demo_cashier, ROLE_CASHIER, "Cajero de turno"),
        ]
        for (username, password), role, full_name in initial:
            if not username or not password:
                continue
            validate_password_strength(password)
            data = UserCreate(username=username, full_name=full_name, password=password, role=role)
            self.create_user(data, actor="sistema")
