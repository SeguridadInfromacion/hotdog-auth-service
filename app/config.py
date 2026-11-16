"""Configuración del servicio, leída únicamente de variables de entorno."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str
    jwt_private_key_file: Path
    jwt_public_key_file: Path
    jwt_issuer: str = "hotdog-auth"
    jwt_audience: str = "hotdog-api"
    access_token_minutes: int = Field(default=60, ge=5, le=480)

    cookie_secure: bool = True
    max_failed_logins: int = Field(default=5, ge=3, le=20)
    lockout_minutes: int = Field(default=15, ge=1, le=1440)

    # Usuarios iniciales: solo se crean si la tabla de usuarios está vacía.
    admin_username: str | None = None
    admin_password: str | None = None
    demo_cashier_username: str | None = None
    demo_cashier_password: str | None = None

    # La documentación interactiva queda apagada salvo que se pida explícitamente.
    enable_docs: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
