"""Administración de usuarios y control de acceso por rol."""

from tests.conftest import CASHIER_PASSWORD

NEW_USER = {
    "username": "lucia",
    "full_name": "Lucía Pérez",
    "password": "Papitas-2026-ok",
    "role": "cashier",
}


def _user_id(admin_client, username):
    users = admin_client.get("/api/users").json()
    return next(user["id"] for user in users if user["username"] == username)


def test_anonymous_cannot_list_users(client):
    assert client.get("/api/users").status_code == 401


def test_cashier_cannot_manage_users(cashier_client):
    assert cashier_client.get("/api/users").status_code == 403
    assert cashier_client.post("/api/users", json=NEW_USER).status_code == 403
    assert cashier_client.get("/api/auth/audit").status_code == 403


def test_admin_creates_a_user_who_can_then_log_in(admin_client, client):
    created = admin_client.post("/api/users", json=NEW_USER)

    assert created.status_code == 201
    assert "password" not in created.text
    login = client.post(
        "/api/auth/login", json={"username": "lucia", "password": NEW_USER["password"]}
    )
    assert login.status_code == 200


def test_duplicate_username_is_a_conflict(admin_client):
    assert admin_client.post("/api/users", json=NEW_USER).status_code == 201
    assert admin_client.post("/api/users", json=NEW_USER).status_code == 409


def test_weak_password_is_rejected(admin_client):
    for weak in ("corta1", "solamenteletras", "12345678901234"):
        response = admin_client.post("/api/users", json={**NEW_USER, "password": weak})
        assert response.status_code == 422, weak


def test_invalid_username_and_role_are_rejected(admin_client):
    assert admin_client.post("/api/users", json={**NEW_USER, "username": "a b"}).status_code == 422
    assert admin_client.post("/api/users", json={**NEW_USER, "role": "root"}).status_code == 422


def test_deactivated_user_is_locked_out_immediately(admin_client, cashier_client):
    cashier_id = _user_id(admin_client, "cajero")

    response = admin_client.patch(f"/api/users/{cashier_id}", json={"is_active": False})

    assert response.status_code == 200
    assert cashier_client.get("/api/auth/me").status_code == 401
    relogin = cashier_client.post(
        "/api/auth/login", json={"username": "cajero", "password": CASHIER_PASSWORD}
    )
    assert relogin.status_code == 401


def test_admin_cannot_deactivate_or_demote_themself(admin_client):
    admin_id = _user_id(admin_client, "admin")

    assert (
        admin_client.patch(f"/api/users/{admin_id}", json={"is_active": False}).status_code == 403
    )
    assert admin_client.patch(f"/api/users/{admin_id}", json={"role": "cashier"}).status_code == 403


def test_update_cannot_touch_fields_outside_the_contract(admin_client):
    cashier_id = _user_id(admin_client, "cajero")
    response = admin_client.patch(f"/api/users/{cashier_id}", json={"password_hash": "x"})
    assert response.status_code == 422


def test_actions_leave_an_audit_trail(admin_client):
    admin_client.post("/api/users", json=NEW_USER)

    actions = [entry["action"] for entry in admin_client.get("/api/auth/audit").json()]

    assert "usuario.crear" in actions
    assert "login.ok" in actions


def test_changing_a_password_ends_that_users_open_sessions(admin_client, cashier_client):
    cashier_id = _user_id(admin_client, "cajero")
    new_password = "Mayonesa-2026-nueva"

    response = admin_client.patch(f"/api/users/{cashier_id}", json={"password": new_password})

    assert response.status_code == 200
    assert cashier_client.get("/api/auth/me").status_code == 401
    old = cashier_client.post(
        "/api/auth/login", json={"username": "cajero", "password": CASHIER_PASSWORD}
    )
    new = cashier_client.post(
        "/api/auth/login", json={"username": "cajero", "password": new_password}
    )
    assert (old.status_code, new.status_code) == (401, 200)


def test_changing_a_role_ends_that_users_open_sessions(admin_client, cashier_client):
    cashier_id = _user_id(admin_client, "cajero")

    admin_client.patch(f"/api/users/{cashier_id}", json={"role": "admin"})

    assert cashier_client.get("/api/auth/me").status_code == 401


def test_renaming_a_user_keeps_their_session(admin_client, cashier_client):
    cashier_id = _user_id(admin_client, "cajero")

    admin_client.patch(f"/api/users/{cashier_id}", json={"full_name": "Carlos Cajero"})

    assert cashier_client.get("/api/auth/me").json()["full_name"] == "Carlos Cajero"


def test_empty_update_is_rejected_and_not_audited(admin_client):
    cashier_id = _user_id(admin_client, "cajero")

    assert admin_client.patch(f"/api/users/{cashier_id}", json={}).status_code == 400
    actions = [entry["action"] for entry in admin_client.get("/api/auth/audit").json()]
    assert "usuario.editar" not in actions


def test_uppercase_usernames_are_rejected_not_silently_changed(admin_client):
    response = admin_client.post("/api/users", json={**NEW_USER, "username": "Lucia"})
    assert response.status_code == 422


def test_line_breaks_in_names_are_rejected(admin_client):
    forged = "Lucía\nINFO audit actor='admin' action='falso'"
    response = admin_client.post("/api/users", json={**NEW_USER, "full_name": forged})
    assert response.status_code == 422
