"""Inicio de sesión, cookie de sesión, bloqueo por intentos y validación de tokens."""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.config import get_settings
from app.database import session_scope
from app.main import create_app
from app.models import LoginThrottle
from tests.conftest import ADMIN_PASSWORD, CSRF_HEADER

WRONG_PASSWORD = "incorrecta-123"


def _login(client, username="admin", password=ADMIN_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _client_from(ip: str) -> TestClient:
    """Un cliente que llega desde otra dirección IP."""
    return TestClient(
        create_app(), base_url="https://testserver", headers=CSRF_HEADER, client=(ip, 50000)
    )


def _lock_admin_from(client) -> None:
    for _ in range(get_settings().max_failed_logins):
        assert _login(client, password=WRONG_PASSWORD).status_code == 401


# --- Inicio de sesión --------------------------------------------------------


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
    wrong_password = _login(client, password=WRONG_PASSWORD)
    unknown_user = _login(client, username="fantasma", password=WRONG_PASSWORD)

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_sql_injection_in_login_is_just_a_wrong_username(client):
    response = _login(client, username="admin' OR '1'='1' --", password="x")
    assert response.status_code == 401


def test_control_characters_in_the_username_are_rejected_cleanly(client):
    response = _login(client, username="adm\x00in", password="x")
    assert response.status_code == 422


def test_validation_errors_never_echo_the_submitted_password(admin_client):
    secret = "SoloLetrasSinNumeros"
    response = admin_client.post(
        "/api/users",
        json={"username": "lucia", "full_name": "Lucía", "password": secret, "role": "cashier"},
    )

    assert response.status_code == 422
    assert secret not in response.text
    assert "letras y números" in response.text


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


# --- Bloqueo por intentos fallidos -------------------------------------------


def test_too_many_failures_lock_that_origin_even_with_the_right_password(client):
    _lock_admin_from(client)
    assert _login(client).status_code == 401


def test_an_attacker_cannot_lock_the_owner_out_from_another_address(client):
    """El bloqueo es por (usuario, IP): fallar a propósito no deja por fuera al dueño."""
    with _client_from("203.0.113.66") as attacker:
        _lock_admin_from(attacker)
        assert _login(attacker).status_code == 401

    assert _login(client).status_code == 200


def test_lock_expires_on_its_own(client):
    _lock_admin_from(client)
    with session_scope() as session:
        session.execute(
            update(LoginThrottle).values(locked_until=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()

    assert _login(client).status_code == 200


def test_old_failures_do_not_add_up_forever(client):
    for _ in range(get_settings().max_failed_logins - 1):
        _login(client, password=WRONG_PASSWORD)
    with session_scope() as session:
        session.execute(
            update(LoginThrottle).values(first_failure_at=datetime.now(UTC) - timedelta(days=30))
        )
        session.commit()

    _login(client, password=WRONG_PASSWORD)  # el quinto fallo, un mes después

    assert _login(client).status_code == 200


def test_successful_login_clears_the_failure_count(client):
    _login(client, password=WRONG_PASSWORD)
    assert _login(client).status_code == 200

    with session_scope() as session:
        assert session.scalars(select(LoginThrottle)).all() == []


def test_lock_is_audited_with_the_origin_address(admin_client):
    with _client_from("203.0.113.66") as attacker:
        _lock_admin_from(attacker)

    trail = admin_client.get("/api/auth/audit").json()
    locks = [entry for entry in trail if entry["action"] == "login.bloqueo"]

    assert [entry["ip"] for entry in locks] == ["203.0.113.66"]


# --- Sesión: consulta, renovación y cierre -----------------------------------


def test_me_requires_a_session(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_logged_in_user(admin_client):
    response = admin_client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "admin"


def test_refresh_issues_a_new_token_for_the_same_session(admin_client):
    old_token = admin_client.cookies["access_token"]

    response = admin_client.post("/api/auth/refresh")

    assert response.status_code == 200
    new_token = admin_client.cookies["access_token"]
    assert new_token != old_token
    started = [
        jwt.decode(token, options={"verify_signature": False})["auth_time"]
        for token in (old_token, new_token)
    ]
    assert started[0] == started[1]


def test_refresh_requires_a_session(client):
    assert client.post("/api/auth/refresh").status_code == 401


def test_a_session_cannot_be_refreshed_past_its_absolute_limit(admin_client):
    settings = get_settings()
    claims = _valid_claims(admin_client)
    too_long_ago = datetime.now(UTC) - timedelta(hours=settings.session_hours, minutes=1)
    claims["auth_time"] = int(too_long_ago.timestamp())
    old_session = jwt.encode(claims, settings.jwt_private_key_file.read_text(), algorithm="RS256")
    admin_client.cookies.set("access_token", old_session)

    assert admin_client.post("/api/auth/refresh").status_code == 401


def test_logout_invalidates_the_token_itself_not_just_the_cookie(admin_client):
    stolen_copy = admin_client.cookies["access_token"]

    assert admin_client.post("/api/auth/logout").status_code == 204

    assert admin_client.get("/api/auth/me").status_code == 401
    assert _bearer(admin_client, stolen_copy).status_code == 401


def test_logout_without_a_session_is_harmless(client):
    assert client.post("/api/auth/logout").status_code == 204


# --- Tokens manipulados ------------------------------------------------------


def _bearer(client, token):
    client.cookies.clear()
    return client.get("/api/auth/me", headers={**CSRF_HEADER, "Authorization": f"Bearer {token}"})


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _valid_claims(client) -> dict:
    return jwt.decode(client.cookies["access_token"], options={"verify_signature": False})


def _signed(claims: dict) -> str:
    private_key = get_settings().jwt_private_key_file.read_text()
    return jwt.encode(claims, private_key, algorithm="RS256")


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
    digest = hmac.new(public_key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert _bearer(admin_client, f"{header}.{payload}.{signature}").status_code == 401


def test_expired_token_is_rejected(admin_client):
    claims = _valid_claims(admin_client)
    claims["exp"] = datetime.now(UTC) - timedelta(minutes=1)
    assert _bearer(admin_client, _signed(claims)).status_code == 401


def test_token_for_another_audience_or_issuer_is_rejected(admin_client):
    claims = _valid_claims(admin_client)
    assert _bearer(admin_client, _signed({**claims, "aud": "otra-app"})).status_code == 401
    assert _bearer(admin_client, _signed({**claims, "iss": "otro-emisor"})).status_code == 401


def test_token_missing_required_claims_is_rejected(admin_client):
    claims = _valid_claims(admin_client)
    for missing in ("exp", "sub", "ver", "auth_time"):
        incomplete = {key: value for key, value in claims.items() if key != missing}
        assert _bearer(admin_client, _signed(incomplete)).status_code == 401, missing
