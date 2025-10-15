from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.main import app
from app.models.auth import User


@pytest.fixture(scope="session", autouse=True)
def patch_jwt():
    with patch("app.utils.jwt_encoder.JWTBearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})):
        yield

@pytest.fixture(autouse=True)
def mock_services():
    with patch("app.controllers.auth_controller.auth_service") as mock_auth:

        mock_auth.read_user_by_email = AsyncMock()
        mock_auth.create_user = AsyncMock()
        mock_auth.validate_password = AsyncMock()
        mock_auth.change_password = AsyncMock()
        mock_auth.revoke_token = AsyncMock()
        mock_auth.is_token_revoked = AsyncMock()
        mock_auth.create_revoked_token = AsyncMock()
        mock_auth.update_user_password = AsyncMock()

        yield mock_auth

        mock_auth.reset_mock()

client = TestClient(app)


# --- SIGNUP ---
def test_signup_success(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = None
    mock_auth.create_user.return_value = None

    response = client.post("/signup", json={
        "email": "test@example.com",
        "password": "13pAssword*"
    })
    assert response.status_code == 200
    assert response.json()["detail"] == "signup_success"


def test_signup_user_exists(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = {"email": "test@example.com"}

    response = client.post("/signup", json={"email": "test@example.com", "password": "13pAssword*"})
    assert response.status_code == 409
    assert response.json()["detail"] == "user_already_exists"


@pytest.mark.parametrize("password,status_code,error_message", [
    ("weak", 422, "Value error, the password must be between 8 and 20 characters"),
    ("weakkaew", 422, "Value error, the password must contain at least one capital letter"),
    ("weAkkaew", 422, "Value error, the password must contain at least one digit"),
    ("1weAkkaew", 422, "Value error, the password must contain at least one special character")
])
def test_signup_fails_with_weak_password(mock_services, password, status_code, error_message):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = None
    mock_auth.create_user.return_value = None

    response = client.post("/signup", json={"email": "test@example.com", "password": password})
    assert response.status_code == status_code
    assert response.json()["detail"] == "validation_error"


def test_signup_wrong_email(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = None

    response = client.post("/signup", json={"email": "some_text", "password": "13pAssword*"})
    assert response.status_code == 422
    assert response.json()["detail"] == "validation_error"


# --- LOGIN ---
def test_login_user_not_exist(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = None

    response = client.post("/login", json={"email": "nouser@example.com", "password": "13pAssword*"})
    assert response.status_code == 400
    assert response.json()["detail"] == "user_no_exist"


def test_login_wrong_password(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.auth_controller.password_encoder.verify", new=AsyncMock(return_value=False)):
        response = client.post("/login", json={"email": "test@example.com", "password": "15pAssword*"})
        assert response.status_code == 400
        assert response.json()["detail"] == "user_incorrect_password"


def test_login_success(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.auth_controller.password_encoder.verify", new=AsyncMock(return_value=True)), \
         patch("app.controllers.auth_controller.jwt_bearer.create_access_token", new=AsyncMock(return_value="access")), \
         patch("app.controllers.auth_controller.jwt_bearer.create_refresh_token", new=AsyncMock(return_value="refresh")), \
         patch("app.controllers.auth_controller.jwt_bearer.set_auth_cookies", new=AsyncMock()):
        response = client.post("/login", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 200
        assert response.json()["detail"] == "login_success"
        assert "user_id" in response.json()


# --- LOGOUT ---
def test_logout_no_refresh_token(mock_services):
    client.cookies.clear()
    client.cookies.set("access_token", "faketoken")
    response = client.post("/logout")
    assert response.status_code == 400
    assert response.json()["detail"] == "missing_refresh_token"


def test_logout_success(mock_services):
    mock_auth = mock_services
    mock_auth.create_revoked_token.return_value = None

    with patch("app.controllers.auth_controller.jwt_bearer.read_expiration_date", new=AsyncMock(return_value=123456)):
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        client.cookies.set("refresh_token", "refresh")
        response = client.post("/logout")
        assert response.status_code == 200
        assert response.json()["detail"] == "logout_success"


# --- ACCOUNT EXISTS ---
def test_account_exists_true(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = {"email": "test@example.com"}

    response = client.post("/account_exists", json={"email": "test@example.com"})
    assert response.status_code == 200
    assert response.json()["user_exists"] is True
    assert response.json()["detail"] == "account_exists_success"


def test_account_exists_false(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = None

    response = client.post("/account_exists", json={"email": "nouser@example.com"})
    assert response.status_code == 200
    assert response.json()["user_exists"] is False
    assert response.json()["detail"] == "account_exists_success"


# --- CHANGE PASSWORD ---
def test_change_password_user_not_exist(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = None

    client.cookies.clear()
    client.cookies.set("access_token", "faketoken")
    response = client.post("/change_password", json={"email": "nouser@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"})
    assert response.status_code == 400
    assert response.json()["detail"] == "user_no_exist"


def test_change_password_invalid_old_password(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.auth_controller.password_encoder.verify", new=AsyncMock(return_value=False)):
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        response = client.post("/change_password", json={"email": "test@example.com", "old_password": "15pAssword*", "new_password": "14pAssword*"})
        assert response.status_code == 400
        assert response.json()["detail"] == "user_invalid_old_password"


def test_change_password_success(mock_services):
    mock_auth = mock_services
    mock_auth.read_user_by_email.return_value = User(email="test@example.com", password="hashed")
    mock_auth.update_user_password.return_value = None

    with patch("app.controllers.auth_controller.password_encoder.verify", new=AsyncMock(return_value=True)), \
         patch("app.controllers.auth_controller.password_encoder.hash", new=AsyncMock(return_value="new_hashed")):
        client.cookies.clear()
        client.cookies.set("access_token", "faketoken")
        response = client.post("/change_password", json={"email": "test@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"})
        assert response.status_code == 200
        assert response.json()["detail"] == "change_password_success"


# --- CHECK TOKEN ---
def test_check_token_missing():
    headers = {"Authorization": "Bearer faketoken"}
    response = client.post("/check_token", json={"token": ""}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "token_missing"


def test_check_token_valid():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", new=AsyncMock(return_value={"user_id": "abc123"})):
        response = client.post("/check_token", json={"token": "sometoken"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["detail"] == "token_verification_success"


def test_check_token_expired():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", new=AsyncMock(side_effect=ExpiredSignatureError)):
        response = client.post("/check_token", json={"token": "expiredtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "token_expired"


def test_check_token_invalid():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.controllers.auth_controller.jwt_bearer.verify_access_token", new=AsyncMock(side_effect=InvalidTokenError)):
        response = client.post("/check_token", json={"token": "invalidtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "token_invalid"


# --- REFRESH TOKEN ---
def test_refresh_token_missing(mock_services):
    headers = {"Authorization": "Bearer faketoken"}
    response = client.post("/refresh_token", headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "missing_refresh_token"


def test_refresh_token_revoked(mock_services):
    mock_auth = mock_services
    mock_auth.is_token_revoked.return_value = True

    with TestClient(app) as test_client:
        test_client.cookies.set("refresh_token", "revokedtoken")
        response = test_client.post("/refresh_token")
        assert response.status_code == 401
        assert response.json()["detail"] == "token_revoked"


def test_refresh_token_success(mock_services):
    mock_auth = mock_services
    mock_auth.is_token_revoked.return_value = False

    with TestClient(app) as test_client:
        test_client.cookies.set("refresh_token", "validtoken")
        with patch("app.controllers.auth_controller.jwt_bearer.verify_refresh_token", new=AsyncMock(return_value={"user_id": "1"})), \
             patch("app.controllers.auth_controller.jwt_bearer.create_access_token", new=AsyncMock(return_value="new_access")):
            response = test_client.post("/refresh_token")
            print(response.json())
            assert response.status_code == 200
            assert response.json()["detail"] == "refresh_token_success"
