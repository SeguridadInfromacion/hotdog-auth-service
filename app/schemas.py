"""Contratos de entrada y salida de la API. Toda entrada se valida aquí."""

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

USERNAME_PATTERN = r"^[a-z0-9_.-]{3,32}$"

Username = Annotated[
    str,
    StringConstraints(strip_whitespace=True, to_lower=True, pattern=USERNAME_PATTERN),
]
FullName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=80)]
Role = Literal["admin", "cashier"]


def validate_password_strength(password: str) -> str:
    if not 10 <= len(password) <= 128:
        raise ValueError("La contraseña debe tener entre 10 y 128 caracteres.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("La contraseña debe incluir letras y números.")
    return password


class StrictModel(BaseModel):
    """Rechaza campos desconocidos: evita la asignación masiva de atributos."""

    model_config = ConfigDict(extra="forbid")


class LoginIn(StrictModel):
    username: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class UserCreate(StrictModel):
    username: Username
    full_name: FullName
    password: str
    role: Role

    _check_password = field_validator("password")(validate_password_strength)


class UserUpdate(StrictModel):
    full_name: FullName | None = None
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = None

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str | None) -> str | None:
        return None if value is None else validate_password_strength(value)


class UserOut(BaseModel):
    """Lo que se devuelve de un usuario. Nunca incluye el hash de la contraseña."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    full_name: str
    role: Role
    is_active: bool
    created_at: datetime


class SessionOut(BaseModel):
    user: UserOut
    expires_at: datetime


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    occurred_at: datetime
    actor: str
    action: str
    target: str
    ip: str
