"""Modelos de la base de datos (el esquema real vive en el repo hotdog-database)."""

import uuid
from datetime import datetime

from sqlalchemy import String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, UtcDateTime, utcnow

ROLE_ADMIN = "admin"
ROLE_CASHIER = "cashier"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    full_name: Mapped[str] = mapped_column(String(80))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    is_active: Mapped[bool] = mapped_column(default=True)
    # Sube cada vez que cambia algo que debe cerrar las sesiones abiertas
    # (contraseña, rol, cierre de sesión). Un token con una versión vieja no vale.
    token_version: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class LoginThrottle(Base):
    """Intentos fallidos de un usuario DESDE una dirección IP.

    El bloqueo es por pareja (usuario, IP): quien falla muchas veces se bloquea
    a sí mismo, pero no puede dejar por fuera al dueño de la cuenta, que entra
    desde otra dirección.
    """

    __tablename__ = "login_throttle"

    username: Mapped[str] = mapped_column(String(32), primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    failed_attempts: Mapped[int] = mapped_column(default=0)
    first_failure_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    locked_until: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)

    def is_locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(120), default="")
    ip: Mapped[str] = mapped_column(String(45), default="")
