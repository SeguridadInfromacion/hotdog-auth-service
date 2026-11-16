"""Acceso a datos. Todas las consultas usan el ORM, que envía los valores
como parámetros: no hay SQL armado con texto del usuario (sin inyección SQL)."""

import logging
import uuid
from collections.abc import Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AuditLog, LoginThrottle, User

audit_logger = logging.getLogger("audit")


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, user_id: uuid.UUID) -> User | None:
        return self._session.get(User, user_id)

    def get_by_username(self, username: str) -> User | None:
        return self._session.scalar(select(User).where(User.username == username))

    def list_all(self) -> Sequence[User]:
        return self._session.scalars(select(User).order_by(User.created_at)).all()

    def count(self) -> int:
        return self._session.scalar(select(func.count()).select_from(User)) or 0

    def add(self, user: User) -> User:
        self._session.add(user)
        self._session.flush()
        return user


class LoginThrottleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_locked(self, username: str, ip: str) -> LoginThrottle | None:
        """Lee la fila bloqueándola (FOR UPDATE): los intentos simultáneos del mismo
        origen se atienden uno por uno y ninguno se queda sin contar."""
        query = (
            select(LoginThrottle)
            .where(LoginThrottle.username == username, LoginThrottle.ip == ip)
            .with_for_update()
        )
        return self._session.scalar(query)

    def start(self, username: str, ip: str) -> LoginThrottle:
        """Crea la fila del primer fallo. Si otro intento simultáneo la creó antes, usa esa."""
        throttle = LoginThrottle(username=username, ip=ip)
        try:
            with self._session.begin_nested():
                self._session.add(throttle)
        except IntegrityError:
            existing = self.get_locked(username, ip)
            if existing is None:
                raise
            return existing
        return throttle

    def delete(self, throttle: LoginThrottle) -> None:
        self._session.delete(throttle)

    def clear_for(self, username: str) -> None:
        self._session.execute(delete(LoginThrottle).where(LoginThrottle.username == username))


class AuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, *, actor: str, action: str, target: str = "", ip: str = "") -> None:
        self._session.add(AuditLog(actor=actor, action=action, target=target[:120], ip=ip[:45]))
        # %r: un salto de línea en un dato no puede falsificar otra línea del log.
        audit_logger.info("actor=%r action=%r target=%r ip=%r", actor, action, target, ip)

    def recent(self, limit: int = 100) -> Sequence[AuditLog]:
        query = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
        return self._session.scalars(query).all()
