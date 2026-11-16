"""Acceso a datos. Todas las consultas usan el ORM, que envía los valores
como parámetros: no hay SQL armado con texto del usuario (sin inyección SQL)."""

import logging
import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditLog, User

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


class AuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, *, actor: str, action: str, target: str = "", ip: str = "") -> None:
        self._session.add(AuditLog(actor=actor, action=action, target=target[:120], ip=ip[:45]))
        audit_logger.info("actor=%s action=%s target=%s ip=%s", actor, action, target, ip)

    def recent(self, limit: int = 100) -> Sequence[AuditLog]:
        query = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
        return self._session.scalars(query).all()
