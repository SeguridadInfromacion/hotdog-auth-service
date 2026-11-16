"""Contraseñas (Argon2id) y tokens de sesión (JWT firmados con RS256)."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.config import get_settings
from app.database import utcnow
from app.errors import NotAuthenticated
from app.models import User

# Se fija el algoritmo: un token con "alg: none" o firmado con HS256 se rechaza.
JWT_ALGORITHM = "RS256"

_hasher = PasswordHasher()

# Hash de relleno: se verifica cuando el usuario no existe para que la respuesta
# tarde lo mismo y no se pueda adivinar qué usuarios existen midiendo tiempos.
DUMMY_HASH = _hasher.hash(uuid.uuid4().hex)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


@dataclass(frozen=True)
class TokenClaims:
    user_id: uuid.UUID
    username: str
    role: str
    token_version: int
    session_started_at: datetime


@lru_cache
def _private_key() -> str:
    return get_settings().jwt_private_key_file.read_text(encoding="utf-8")


@lru_cache
def _public_key() -> str:
    return get_settings().jwt_public_key_file.read_text(encoding="utf-8")


def issue_token(user: User, session_started_at: datetime | None = None) -> tuple[str, datetime]:
    """Firma un token para el usuario. Devuelve el token y cuándo vence.

    Al renovar se conserva session_started_at: así la sesión tiene un tope absoluto.
    """
    settings = get_settings()
    issued_at = utcnow()
    session_started_at = session_started_at or issued_at
    expires_at = issued_at + timedelta(minutes=settings.access_token_minutes)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "name": user.full_name,
        "role": user.role,
        "ver": user.token_version,
        "auth_time": int(session_started_at.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": issued_at,
        "exp": expires_at,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _private_key(), algorithm=JWT_ALGORITHM), expires_at


def decode_token(token: str) -> TokenClaims:
    """Verifica firma, vencimiento, emisor y audiencia. Falla con NotAuthenticated."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            _public_key(),
            algorithms=[JWT_ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        return TokenClaims(
            user_id=uuid.UUID(payload["sub"]),
            username=str(payload["username"]),
            role=str(payload["role"]),
            token_version=int(payload["ver"]),
            session_started_at=datetime.fromtimestamp(int(payload["auth_time"]), UTC),
        )
    except (
        jwt.InvalidTokenError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        OSError,
    ) as error:
        raise NotAuthenticated("Tu sesión no es válida o ya venció.") from error
