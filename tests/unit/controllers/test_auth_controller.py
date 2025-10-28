from unittest.mock import AsyncMock, patch

import pytest
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.models.auth import User


@pytest.fixture(scope="session", autouse=True)
def patch_jwt():
    with patch("app.controllers.auth_controller.jwt_bearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})):
        yield


# --- SIGNUP ---
def test_signup_success(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = None
    mock_auth_service.create_user.return_value = None

    response = client.post("/signup", json={
        "email": "test@example.com",
        "password": "13pAssword*"
    })
    assert response.status_code == 200
    assert response.json()["detail"] == "signup_success"


def test_signup_user_exists(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = {"email": "test@example.com"}

    response = client.post("/signup", json={"email": "test@example.com", "password": "13pAssword*"})
    assert response.status_code == 409
    assert response.json()["detail"] == "user_already_exists"


@pytest.mark.parametrize("password,status_code,error_message", [
    ("weak", 422, "Value error, the password must be between 8 and 20 characters"),
    ("weakkaew", 422, "Value error, the password must contain at least one capital letter"),
    ("weAkkaew", 422, "Value error, the password must contain at least one digit"),
    ("1weAkkaew", 422, "Value error, the password must contain at least one special character")
])
def test_signup_fails_with_weak_password(client, mock_auth_service, password, status_code, error_message):
    mock_auth_service.read_user_by_email.return_value = None
    mock_auth_service.create_user.return_value = None

    response = client.post("/signup", json={"email": "test@example.com", "password": password})
    assert response.status_code == status_code
    assert response.json()["detail"] == "validation_error"


def test_signup_wrong_email(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = None

    response = client.post("/signup", json={"email": "some_text", "password": "13pAssword*"})
    assert response.status_code == 422
    assert response.json()["detail"] == "validation_error"


# --- LOGIN ---
def test_login_user_not_exist(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = None

    response = client.post("/login", json={"email": "nouser@example.com", "password": "13pAssword*"})
    assert response.status_code == 400
    assert response.json()["detail"] == "user_no_exist"


def test_login_wrong_password(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.auth_controller.password_encoder.verify", return_value=False):
        response = client.post("/login", json={"email": "test@example.com", "password": "15pAssword*"})
        assert response.status_code == 400
        assert response.json()["detail"] == "user_incorrect_password"


def test_login_success(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.auth_controller.password_encoder.verify", return_value=True), \
         patch("app.controllers.auth_controller.jwt_bearer.create_access_token", return_value="access"), \
         patch("app.controllers.auth_controller.jwt_bearer.create_refresh_token", return_value="refresh"), \
         patch("app.controllers.auth_controller.jwt_bearer.set_auth_cookies"):
        response = client.post("/login", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 200
        assert response.json()["detail"] == "login_success"
        assert "user_id" in response.json()


# --- LOGOUT ---
def test_logout_no_refresh_token(client, mock_auth_service):
    headers = {"Authorization": "Bearer faketoken"}
    client.cookies.clear()
    client.cookies.set("access_token", "faketoken")
    response = client.post("/logout", headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "missing_refresh_token"


def test_logout_success(client, mock_auth_service):
    mock_auth_service.create_revoked_token.return_value = None

    with patch("app.controllers.auth_controller.jwt_bearer.read_expiration_date", return_value=123456):
        headers = {"Authorization": "Bearer faketoken"}
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        client.cookies.set("refresh_token", "refresh")
        response = client.post("/logout", headers=headers)
        assert response.status_code == 200
        assert response.json()["detail"] == "logout_success"


# --- ACCOUNT EXISTS ---
def test_account_exists_true(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = {"email": "test@example.com"}

    response = client.post("/account_exists", json={"email": "test@example.com"})
    assert response.status_code == 200
    assert response.json()["user_exists"] is True
    assert response.json()["detail"] == "account_exists_success"


def test_account_exists_false(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = None

    response = client.post("/account_exists", json={"email": "nouser@example.com"})
    assert response.status_code == 200
    assert response.json()["user_exists"] is False
    assert response.json()["detail"] == "account_exists_success"


# --- CHANGE PASSWORD ---
def test_change_password_user_not_exist(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = None

    headers = {"Authorization": "Bearer faketoken"}
    client.cookies.clear()
    client.cookies.set("access_token", "faketoken")
    response = client.post("/change_password", json={"email": "nouser@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "user_no_exist"


def test_change_password_invalid_old_password(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.auth_controller.password_encoder.verify", return_value=False):
        headers = {"Authorization": "Bearer faketoken"}
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        response = client.post("/change_password", json={"email": "test@example.com", "old_password": "15pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"] == "user_invalid_old_password"


def test_change_password_success(client, mock_auth_service):
    mock_auth_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")
    mock_auth_service.update_user_password.return_value = None

    with patch("app.controllers.auth_controller.password_encoder.verify", return_value=True), \
         patch("app.controllers.auth_controller.password_encoder.hash", return_value="new_hashed"):
        headers = {"Authorization": "Bearer faketoken"}
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        response = client.post("/change_password", json={"email": "test@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["detail"] == "change_password_success"


# --- CHECK TOKEN ---
def test_check_token_missing(client):
    headers = {"Authorization": "Bearer faketoken"}
    response = client.post("/check_token", json={"token": ""}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "token_missing"


def test_check_token_valid(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/check_token", json={"token": "sometoken"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["detail"] == "token_verification_success"


def test_check_token_expired(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", side_effect=ExpiredSignatureError):
        response = client.post("/check_token", json={"token": "expiredtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "token_expired"


def test_check_token_invalid(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", side_effect=InvalidTokenError):
        response = client.post("/check_token", json={"token": "invalidtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "token_invalid"


def test_check_token_unexpected_error(client):
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", side_effect=Exception("Unexpected error")):
        response = client.post("/check_token", json={"token": "badtoken"}, headers=headers)
        assert response.status_code == 500
        assert response.json()["detail"] == "token_error"


# --- REFRESH TOKEN ---
def test_refresh_token_missing(client, mock_auth_service):
    headers = {"Authorization": "Bearer faketoken"}
    response = client.post("/refresh_token", headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "missing_refresh_token"


def test_refresh_token_revoked(client, mock_auth_service):
    mock_auth_service.is_token_revoked.return_value = True

    client.cookies.set("refresh_token", "revokedtoken")
    response = client.post("/refresh_token")
    assert response.status_code == 401
    assert response.json()["detail"] == "token_revoked"


def test_refresh_token_success(client, mock_auth_service):
    mock_auth_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "validtoken")
    with patch("app.controllers.auth_controller.jwt_bearer.verify_refresh_token", return_value={"user_id": "1"}), \
         patch("app.controllers.auth_controller.jwt_bearer.create_access_token", return_value="new_access"):
        response = client.post("/refresh_token")
        print(response.json())
        assert response.status_code == 200
        assert response.json()["detail"] == "refresh_token_success"


def test_refresh_token_expired(client, mock_auth_service):
    mock_auth_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "expiredtoken")
    with patch("app.controllers.auth_controller.jwt_bearer.verify_refresh_token", side_effect=ExpiredSignatureError):
        response = client.post("/refresh_token")
        assert response.status_code == 401
        assert response.json()["detail"] == "token_expired"


def test_refresh_token_invalid(client, mock_auth_service):
    mock_auth_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "invalidtoken")
    with patch("app.controllers.auth_controller.jwt_bearer.verify_refresh_token", side_effect=InvalidTokenError):
        response = client.post("/refresh_token")
        assert response.status_code == 401
        assert response.json()["detail"] == "token_invalid"


def test_refresh_token_unexpected_error(client, mock_auth_service):
    mock_auth_service.is_token_revoked.return_value = False

    client.cookies.set("refresh_token", "badtoken")
    with patch("app.controllers.auth_controller.jwt_bearer.verify_refresh_token", side_effect=Exception("Unexpected error")):
        response = client.post("/refresh_token")
        assert response.status_code == 500
        assert response.json()["detail"] == "token_error"

