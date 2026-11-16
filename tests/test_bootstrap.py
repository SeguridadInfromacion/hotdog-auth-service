"""Creación de los usuarios iniciales al arrancar con la base vacía."""

import pytest
from sqlalchemy import delete

from app.database import session_scope
from app.models import User
from app.services import UserService

ADMIN = ("jefe", "Mostaza-2026-jefe")
CASHIER = ("caja1", "Ketchup-2026-caja")


@pytest.fixture
def empty_users():
    with session_scope() as session:
        session.execute(delete(User))
        session.commit()
        yield session


def _roles(session) -> dict[str, str]:
    return {user.username: user.role for user in UserService(session).list_users()}


def test_creates_admin_and_demo_cashier_on_an_empty_database(empty_users):
    UserService(empty_users).ensure_initial_users(admin=ADMIN, demo_cashier=CASHIER)
    assert _roles(empty_users) == {"jefe": "admin", "caja1": "cashier"}


def test_does_nothing_when_users_already_exist():
    with session_scope() as session:
        UserService(session).ensure_initial_users(admin=ADMIN, demo_cashier=CASHIER)
        assert "jefe" not in _roles(session)


def test_refuses_to_start_without_an_admin(empty_users):
    with pytest.raises(RuntimeError):
        UserService(empty_users).ensure_initial_users(admin=(None, None), demo_cashier=CASHIER)
    assert _roles(empty_users) == {}


def test_refuses_a_weak_initial_password(empty_users):
    with pytest.raises(ValueError):
        UserService(empty_users).ensure_initial_users(
            admin=("jefe", "corta"), demo_cashier=(None, None)
        )
