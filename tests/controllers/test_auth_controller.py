from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.main import app
from app.models.auth import User

client = TestClient(app)

# --- SIGNUP ---
def test_signup_success():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)), \
         patch("app.controllers.auth_controller.create_user", new=AsyncMock()):
        response = client.post("/signup", json={
            "email": "test@example.com",
            "password": "13pAssword*"
        })
        assert response.status_code == 200
        assert response.json()["detail"] == "signup_success"


def test_signup_user_exists():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"email": "test@example.com"})):
        response = client.post("/signup", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 409
        assert response.json()["detail"] == "user_already_exists"


@pytest.mark.parametrize("password,status_code,error_message", [
    ("weak", 422, "Value error, the password must be between 8 and 20 characters"),
    ("weakkaew", 422, "Value error, the password must contain at least one capital letter"),
    ("weAkkaew", 422, "Value error, the password must contain at least one digit"),
    ("1weAkkaew", 422, "Value error, the password must contain at least one special character")
])
def test_signup_fails_with_weak_password(password, status_code, error_message):
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)), \
         patch("app.controllers.auth_controller.create_user", new=AsyncMock()):
        response = client.post("/signup", json={"email": "test@example.com", "password": password})
        assert response.status_code == status_code
        assert response.json()["detail"] == "validation_error"


def test_signup_wrong_email():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/signup", json={"email": "some_text", "password": "13pAssword*"})
        assert response.status_code == 422
        assert response.json()["detail"] == "validation_error"


# --- LOGIN ---
def test_login_user_not_exist():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/login", json={"email": "nouser@example.com", "password": "13pAssword*"})
        assert response.status_code == 400
        assert response.json()["detail"] == "user_no_exist"


def test_login_wrong_password():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=User(email= "test@example.com", password="hashed"))), \
         patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=False)):
        response = client.post("/login", json={"email": "test@example.com", "password": "15pAssword*"})
        assert response.status_code == 400
        assert response.json()["detail"] == "user_incorrect_password"


def test_login_success():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=User(email= "test@example.com", password="hashed"))), \
         patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=True)), \
         patch("app.controllers.auth_controller.create_access_token", new=AsyncMock(return_value="access")), \
         patch("app.controllers.auth_controller.create_refresh_token", new=AsyncMock(return_value="refresh")):
        response = client.post("/login", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 200
        assert response.json()["detail"] == "login_success"
        assert "user_id" in response.json()


# --- LOGOUT ---
def test_logout_no_refresh_token():
    with TestClient(app) as test_client:
        test_client.cookies.set("access_token", "faketoken")
        with patch("app.utils.jwt_encoder.JWTBearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})):
            response = test_client.post("/logout")
            assert response.status_code == 400
            assert response.json()["detail"] == "missing_refresh_token"


def test_logout_success():
    with TestClient(app) as test_client:
        test_client.cookies.set("access_token", "faketoken")
        test_client.cookies.set("refresh_token", "refresh")
        with patch("app.utils.jwt_encoder.JWTBearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})), \
             patch("app.controllers.auth_controller.create_revoked_token", new=AsyncMock()), \
             patch("app.controllers.auth_controller.read_expiration_date", new=AsyncMock(return_value=123456)):
            response = test_client.post("/logout")
            assert response.status_code == 200
            assert response.json()["detail"] == "logout_success"


# --- ACCOUNT EXISTS ---
def test_account_exists_true():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"email": "test@example.com"})):
        response = client.post("/account_exists", json={"email": "test@example.com"})
        assert response.status_code == 200
        assert response.json()["user_exists"] is True
        assert response.json()["detail"] == "account_exists_success"


def test_account_exists_false():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/account_exists", json={"email": "nouser@example.com"})
        assert response.status_code == 200
        assert response.json()["user_exists"] is False
        assert response.json()["detail"] == "account_exists_success"


# --- CHANGE PASSWORD ---
def test_change_password_user_not_exist():
    with TestClient(app) as test_client:
        test_client.cookies.set("access_token", "faketoken")
        with patch("app.utils.jwt_encoder.JWTBearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})), \
            patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
            response = test_client.post("/change_password", json={"email": "nouser@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"})
            assert response.status_code == 400
            assert response.json()["detail"] == "user_no_exist"


def test_change_password_invalid_old_password():
    with TestClient(app) as test_client:
        test_client.cookies.set("access_token", "faketoken")
        with patch("app.utils.jwt_encoder.JWTBearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})), \
             patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=User(email="test@example.com", password="hashed"))), \
             patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=False)):
            response = test_client.post("/change_password", json={"email": "test@example.com", "old_password": "15pAssword*", "new_password": "14pAssword*"})
            assert response.status_code == 400
            assert response.json()["detail"] == "user_invalid_old_password"


def test_change_password_success():
    with TestClient(app) as test_client:
        test_client.cookies.set("access_token", "faketoken")
        with patch("app.utils.jwt_encoder.JWTBearer.__call__", new=AsyncMock(return_value={"user_id": "abc123"})), \
             patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=User(email="test@example.com", password="hashed"))), \
             patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=True)), \
             patch("app.controllers.auth_controller.get_hashed_password", new=AsyncMock(return_value="new_hashed")), \
             patch("app.controllers.auth_controller.update_user_password", new=AsyncMock()):
            response = test_client.post("/change_password", json={"email": "test@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"})
            assert response.status_code == 200
            assert response.json()["detail"] == "change_password_success"


# --- CHECK TOKEN ---
def test_check_token_missing():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/check_token", json={"token": ""}, headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"] == "token_missing"


def test_check_token_valid():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.verify_access_token", new=AsyncMock(return_value={"user_id": "abc123"})):
        response = client.post("/check_token", json={"token": "sometoken"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["detail"] == "token_verification_success"


def test_check_token_expired():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
        patch("app.controllers.auth_controller.verify_access_token", new=AsyncMock(side_effect=ExpiredSignatureError)):
        response = client.post("/check_token", json={"token": "expiredtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "token_expired"


def test_check_token_invalid():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
        patch("app.controllers.auth_controller.verify_access_token", new=AsyncMock(side_effect=InvalidTokenError)):
        response = client.post("/check_token", json={"token": "invalidtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "token_invalid"


# --- REFRESH TOKEN ---
def test_refresh_token_missing():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/refresh_token", headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"] == "missing_refresh_token"


def test_refresh_token_revoked():
    with TestClient(app) as test_client:
        test_client.cookies.set("refresh_token", "revokedtoken")
        with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
             patch("app.controllers.auth_controller.is_token_revoked", new=AsyncMock(return_value=True)):
            response = test_client.post("/refresh_token")
            assert response.status_code == 401
            assert response.json()["detail"] == "token_revoked"


def test_refresh_token_success():
    with TestClient(app) as test_client:
        test_client.cookies.set("refresh_token", "validtoken")
        with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
             patch("app.controllers.auth_controller.is_token_revoked", new=AsyncMock(return_value=False)), \
             patch("app.controllers.auth_controller.verify_refresh_token", new=AsyncMock(return_value={"user_id": "1"})), \
             patch("app.controllers.auth_controller.create_access_token", new=AsyncMock(return_value="new_access")):
            response = test_client.post("/refresh_token")
            print(response.json())
            assert response.status_code == 200
            assert response.json()["detail"] == "refresh_token_success"
