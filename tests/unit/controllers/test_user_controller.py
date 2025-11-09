from unittest.mock import AsyncMock, patch

import pytest
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.models.auth import User


@pytest.fixture(scope="session", autouse=True)
def patch_jwt():
    with patch("app.controllers.user_controller.jwt_bearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})):
        yield


# --- SIGNUP ---
def test_signup_success(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = None
    mock_user_service.create_user.return_value = None

    response = client.post("/user/signup", json={
        "email": "test@example.com",
        "password": "13pAssword*"
    })
    assert response.status_code == 200
    assert response.json()["code"] == "signup_success"
    assert "message" in response.json()


def test_signup_user_exists(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = {"email": "test@example.com"}

    response = client.post("/user/signup", json={"email": "test@example.com", "password": "13pAssword*"})
    assert response.status_code == 409
    assert response.json()["code"] == "user_already_exists"
    assert "message" in response.json()


@pytest.mark.parametrize("password,status_code,error_message", [
    ("weak", 422, "Value error, the password must be between 8 and 20 characters"),
    ("weakkaew", 422, "Value error, the password must contain at least one capital letter"),
    ("weAkkaew", 422, "Value error, the password must contain at least one digit"),
    ("1weAkkaew", 422, "Value error, the password must contain at least one special character")
])
def test_signup_fails_with_weak_password(client, mock_user_service, password, status_code, error_message):
    mock_user_service.read_user_by_email.return_value = None
    mock_user_service.create_user.return_value = None

    response = client.post("/user/signup", json={"email": "test@example.com", "password": password})
    assert response.status_code == status_code
    assert response.json()["code"] == "validation_error"
    assert "message" in response.json()


def test_signup_wrong_email(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = None

    response = client.post("/user/signup", json={"email": "some_text", "password": "13pAssword*"})
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"
    assert "message" in response.json()


# --- LOGIN ---
def test_login_user_not_exist(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = None

    response = client.post("/user/login", json={"email": "nouser@example.com", "password": "13pAssword*"})
    assert response.status_code == 400
    assert response.json()["code"] == "user_not_found"
    assert "message" in response.json()


def test_login_wrong_password(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.user_controller.password_encoder.verify", return_value=False):
        response = client.post("/user/login", json={"email": "test@example.com", "password": "15pAssword*"})
        assert response.status_code == 400
        assert response.json()["code"] == "incorrect_password"
        assert "message" in response.json()


def test_login_success(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.user_controller.password_encoder.verify", return_value=True), \
         patch("app.controllers.user_controller.jwt_bearer.create_access_token", return_value="access"), \
         patch("app.controllers.user_controller.jwt_bearer.create_refresh_token", return_value="refresh"), \
         patch("app.controllers.user_controller.jwt_bearer.set_auth_cookies"):
        response = client.post("/user/login", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 200
        assert response.json()["code"] == "login_success"
        assert "message" in response.json()


# --- LOGOUT ---
def test_logout_no_refresh_token(client, mock_user_service):
    headers = {"Authorization": "Bearer faketoken"}
    client.cookies.clear()
    client.cookies.set("access_token", "faketoken")
    response = client.post("/user/logout", headers=headers)
    assert response.status_code == 400
    assert response.json()["code"] == "missing_refresh_token"
    assert "message" in response.json()


def test_logout_success(client, mock_user_service):
    mock_user_service.create_revoked_token.return_value = None

    with patch("app.controllers.user_controller.jwt_bearer.read_expiration_date", return_value=123456):
        headers = {"Authorization": "Bearer faketoken"}
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        client.cookies.set("refresh_token", "refresh")
        response = client.post("/user/logout", headers=headers)
        assert response.status_code == 200
        assert response.json()["code"] == "logout_success"
        assert "message" in response.json()


# --- ACCOUNT EXISTS ---
def test_account_exists_true(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = {"email": "test@example.com"}

    response = client.post("/user/account_exists", json={"email": "test@example.com"})
    assert response.status_code == 200
    assert response.json()["user_exists"] is True
    assert response.json()["code"] == "account_exists_success"
    assert "message" in response.json()


def test_account_exists_false(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = None

    response = client.post("/user/account_exists", json={"email": "nouser@example.com"})
    assert response.status_code == 200
    assert response.json()["user_exists"] is False
    assert response.json()["code"] == "account_exists_success"
    assert "message" in response.json()


# --- CHANGE PASSWORD ---
def test_change_password_user_not_exist(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = None

    headers = {"Authorization": "Bearer faketoken"}
    client.cookies.clear()
    client.cookies.set("access_token", "faketoken")
    response = client.post("/user/change_password", json={"email": "nouser@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"}, headers=headers)
    assert response.status_code == 400
    assert response.json()["code"] == "user_not_found"
    assert "message" in response.json()


def test_change_password_invalid_old_password(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.user_controller.password_encoder.verify", return_value=False):
        headers = {"Authorization": "Bearer faketoken"}
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        response = client.post("/user/change_password", json={"email": "test@example.com", "old_password": "15pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_old_password"
        assert "message" in response.json()


def test_change_password_success(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")
    mock_user_service.update_user_password.return_value = None

    with patch("app.controllers.user_controller.password_encoder.verify", return_value=True), \
         patch("app.controllers.user_controller.password_encoder.hash", return_value="new_hashed"):
        headers = {"Authorization": "Bearer faketoken"}
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        response = client.post("/user/change_password", json={"email": "test@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["code"] == "change_password_success"
        assert "message" in response.json()


# --- CHECK TOKEN ---
def test_check_token_missing(client):
    headers = {"Authorization": "Bearer faketoken"}
    response = client.post("/user/check_token", json={"token": ""}, headers=headers)
    assert response.status_code == 400
    assert response.json()["code"] == "token_missing"
    assert "message" in response.json()


def test_check_token_valid(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.user_controller.jwt_bearer.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/user/check_token", json={"token": "sometoken"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["code"] == "token_valid"
        assert "message" in response.json()


def test_check_token_expired(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.user_controller.jwt_bearer.verify_access_token", side_effect=ExpiredSignatureError):
        response = client.post("/user/check_token", json={"token": "expiredtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["code"] == "token_expired"
        assert "message" in response.json()


def test_check_token_invalid(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.user_controller.jwt_bearer.verify_access_token", side_effect=InvalidTokenError):
        response = client.post("/user/check_token", json={"token": "invalidtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["code"] == "token_invalid"
        assert "message" in response.json()


def test_check_token_unexpected_error(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.user_controller.jwt_bearer.verify_access_token", side_effect=Exception("Unexpected error")):
        response = client.post("/user/check_token", json={"token": "badtoken"}, headers=headers)
        assert response.status_code == 500
        assert response.json()["code"] == "token_error"
        assert "message" in response.json()


# --- REFRESH TOKEN ---
def test_refresh_token_missing(client, mock_user_service):
    headers = {"Authorization": "Bearer faketoken"}
    response = client.post("/user/refresh_token", headers=headers)
    assert response.status_code == 400
    assert response.json()["code"] == "missing_refresh_token"
    assert "message" in response.json()


def test_refresh_token_revoked(client, mock_user_service):
    mock_user_service.is_token_revoked.return_value = True

    client.cookies.set("refresh_token", "revokedtoken")
    response = client.post("/user/refresh_token")
    assert response.status_code == 401
    assert response.json()["code"] == "token_revoked"
    assert "message" in response.json()


def test_refresh_token_success(client, mock_user_service):
    mock_user_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "validtoken")
    with patch("app.controllers.user_controller.jwt_bearer.verify_refresh_token", return_value={"user_id": "1"}), \
         patch("app.controllers.user_controller.jwt_bearer.create_access_token", return_value="new_access"):
        response = client.post("/user/refresh_token")
        print(response.json())
        assert response.status_code == 200
        assert response.json()["code"] == "refresh_token_success"
        assert "message" in response.json()


def test_refresh_token_expired(client, mock_user_service):
    mock_user_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "expiredtoken")
    with patch("app.controllers.user_controller.jwt_bearer.verify_refresh_token", side_effect=ExpiredSignatureError):
        response = client.post("/user/refresh_token")
        assert response.status_code == 401
        assert response.json()["code"] == "token_expired"
        assert "message" in response.json()


def test_refresh_token_invalid(client, mock_user_service):
    mock_user_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "invalidtoken")
    with patch("app.controllers.user_controller.jwt_bearer.verify_refresh_token", side_effect=InvalidTokenError):
        response = client.post("/user/refresh_token")
        assert response.status_code == 401
        assert response.json()["code"] == "token_invalid"
        assert "message" in response.json()


def test_refresh_token_unexpected_error(client, mock_user_service):
    mock_user_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "badtoken")
    with patch("app.controllers.user_controller.jwt_bearer.verify_refresh_token", side_effect=Exception("Unexpected error")):
        response = client.post("/user/refresh_token")
        assert response.status_code == 500
        assert response.json()["code"] == "token_error"
        assert "message" in response.json()

