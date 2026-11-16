"""Entorno de pruebas: llaves RSA temporales y base SQLite en memoria."""

import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _write_test_keys() -> tuple[Path, Path]:
    directory = Path(tempfile.mkdtemp(prefix="hotdog-keys-"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = directory / "private.pem"
    public_path = directory / "public.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private_path, public_path


_private, _public = _write_test_keys()
os.environ.update(
    DATABASE_URL="sqlite+pysqlite:///:memory:",
    JWT_PRIVATE_KEY_FILE=str(_private),
    JWT_PUBLIC_KEY_FILE=str(_public),
)

# Los imports de la app van después de preparar el entorno.
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, get_engine, session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.schemas import UserCreate  # noqa: E402
from app.services import UserService  # noqa: E402

ADMIN_PASSWORD = "Mostaza-2026-admin"
CASHIER_PASSWORD = "Ketchup-2026-caja"
CSRF_HEADER = {"X-Requested-With": "XMLHttpRequest"}


@pytest.fixture(autouse=True)
def _fresh_database():
    Base.metadata.drop_all(get_engine())
    Base.metadata.create_all(get_engine())
    with session_scope() as session:
        service = UserService(session)
        service.create_user(
            UserCreate(
                username="admin", full_name="Ana Admin", password=ADMIN_PASSWORD, role="admin"
            ),
            actor="test",
        )
        service.create_user(
            UserCreate(
                username="cajero",
                full_name="Carlos Caja",
                password=CASHIER_PASSWORD,
                role="cashier",
            ),
            actor="test",
        )
    yield


def _new_client() -> TestClient:
    return TestClient(create_app(), base_url="https://testserver", headers=CSRF_HEADER)


@pytest.fixture
def client():
    with _new_client() as test_client:
        yield test_client


def _logged_in(username: str, password: str):
    with _new_client() as test_client:
        response = test_client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200, response.text
        yield test_client


@pytest.fixture
def admin_client():
    yield from _logged_in("admin", ADMIN_PASSWORD)


@pytest.fixture
def cashier_client():
    yield from _logged_in("cajero", CASHIER_PASSWORD)
