"""Inicio de sesión, cookie de sesión y validación de tokens."""

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt

from app.config import get_settings
from tests.conftest import ADMIN_PASSWORD, CSRF_HEADER


def _login(client, username="admin", password=ADMIN_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_login_sets_a_hardened_session_cookie(client):
    response = _login(client)

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie


def test_login_response_never_exposes_the_password_hash(client):
    body = _login(client).text
    assert "password" not in body
    assert "argon2" not in body


def test_token_is_not_returned_in_the_response_body(client):
    response = _login(client)
    assert response.cookies["access_token"] not in response.text


def test_wrong_password_and_unknown_user_get_the_same_answer(client):
    wrong_password = _login(client, password="no-es-la-clave-1")
    unknown_user = _login(client, username="fantasma", password="no-es-la-clave-1")

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_sql_injection_in_login_is_just_a_wrong_username(client):
    response = _login(client, username="admin' OR '1'='1' --", password="x")
    assert response.status_code == 401


def test_account_locks_after_too_many_failures(client):
    for _ in range(get_settings().max_failed_logins):
        assert _login(client, password="incorrecta-123").status_code == 401

    # Ni siquiera la contraseña correcta entra mientras dura el bloqueo.
    assert _login(client).status_code == 401


def test_me_requires_a_session(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_logged_in_user(admin_client):
    response = admin_client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "admin"


def test_logout_clears_the_cookie(admin_client):
    assert admin_client.post("/api/auth/logout").status_code == 204
    assert admin_client.get("/api/auth/me").status_code == 401


def test_state_changing_requests_need_the_csrf_header(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD},
        headers={"X-Requested-With": ""},
    )
    assert response.status_code == 403


def test_unknown_fields_are_rejected(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "role": "admin"},
    )
    assert response.status_code == 422


def test_responses_are_never_cached(admin_client):
    assert admin_client.get("/api/auth/me").headers["cache-control"] == "no-store"


# --- Tokens manipulados ------------------------------------------------------


def _bearer(client, token):
    client.cookies.clear()
    return client.get("/api/auth/me", headers={**CSRF_HEADER, "Authorization": f"Bearer {token}"})


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _valid_claims(admin_client) -> dict:
    token = admin_client.cookies["access_token"]
    return jwt.decode(token, options={"verify_signature": False})


def test_valid_token_also_works_as_bearer(admin_client):
    token = admin_client.cookies["access_token"]
    assert _bearer(admin_client, token).status_code == 200


def test_token_with_tampered_payload_is_rejected(admin_client):
    header, _, signature = admin_client.cookies["access_token"].split(".")
    claims = {**_valid_claims(admin_client), "username": "otro"}
    assert _bearer(admin_client, f"{header}.{_b64(claims)}.{signature}").status_code == 401


def test_unsigned_token_is_rejected(admin_client):
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(_valid_claims(admin_client))}."
    assert _bearer(admin_client, forged).status_code == 401


def test_token_signed_with_the_public_key_as_hmac_secret_is_rejected(admin_client):
    """Ataque de confusión de algoritmo (RS256 -> HS256)."""
    public_key = get_settings().jwt_public_key_file.read_bytes()
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64(_valid_claims(admin_client))
    import hashlib
    import hmac

    digest = hmac.new(public_key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert _bearer(admin_client, f"{header}.{payload}.{signature}").status_code == 401


def test_expired_token_is_rejected(admin_client):
    settings = get_settings()
    claims = _valid_claims(admin_client)
    claims["exp"] = datetime.now(UTC) - timedelta(minutes=1)
    expired = jwt.encode(claims, settings.jwt_private_key_file.read_text(), algorithm="RS256")
    assert _bearer(admin_client, expired).status_code == 401


def test_token_for_another_audience_is_rejected(admin_client):
    settings = get_settings()
    claims = {**_valid_claims(admin_client), "aud": "otra-aplicacion"}
    foreign = jwt.encode(claims, settings.jwt_private_key_file.read_text(), algorithm="RS256")
    assert _bearer(admin_client, foreign).status_code == 401
