import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

client = TestClient(app)

# --- SIGNUP ---
def test_signup_success():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)), \
         patch("app.controllers.auth_controller.create_user", new=AsyncMock()):
        response = client.post("/auth/signup", json={
            "email": "test@example.com",
            "password": "13pAssword*"
        })
        assert response.status_code == 200
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "User created successfully"


def test_signup_user_exists():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"email": "test@example.com"})):
        response = client.post("/auth/signup", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 409
        assert response.json()["code"] == "user_already_exists"
        assert response.json()["message"] == "User with this email already exists"


@pytest.mark.parametrize("password,status_code,error_message", [
    ("weak", 422, "String should have at least 8 characters"),
    ("weakkaew", 422, "Value error, the password must contain at least one capital letter"),
    ("weAkkaew", 422, "Value error, the password must contain at least one digit"),
    ("1weAkkaew", 422, "Value error, the password must contain at least one special character")
])
def test_signup_fails_with_weak_password(password, status_code, error_message):
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)), \
         patch("app.controllers.auth_controller.create_user", new=AsyncMock()):
        response = client.post("/auth/signup", json={"email": "test@example.com", "password": password})
        assert response.status_code == status_code
        assert response.json()["code"] == "validation_error"
        assert response.json()["message"] == error_message


def test_signup_wrong_email():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/auth/signup", json={"email": "some_text", "password": "13pAssword*"})
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"
        assert response.json()["message"] == "value is not a valid email address: An email address must have an @-sign."


# --- LOGIN ---
def test_login_user_not_exist():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/auth/login", json={"email": "nouser@example.com", "password": "13pAssword*"})
        assert response.status_code == 400
        assert response.json()["code"] == "user_no_exist"
        assert response.json()["message"] == "User with this email does not exist"


def test_login_wrong_password():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"_id": "1", "password": "hashed"})), \
         patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=False)):
        response = client.post("/auth/login", json={"email": "test@example.com", "password": "15pAssword*"})
        assert response.status_code == 400
        assert response.json()["code"] == "Incorrect password"
        assert response.json()["message"] == "The password provided is incorrect"


def test_login_success():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"_id": "1", "password": "hashed"})), \
         patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=True)), \
         patch("app.controllers.auth_controller.create_access_token", new=AsyncMock(return_value="access")), \
         patch("app.controllers.auth_controller.create_refresh_token", new=AsyncMock(return_value="refresh")):
        response = client.post("/auth/login", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 200
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "Login successful"
        assert "access_token" in response.json()


# --- LOGOUT ---
def test_logout_no_refresh_token():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/auth/logout", headers=headers)
        assert response.status_code == 400
        assert response.json()["code"] == "missing_refresh_token"
        assert response.json()["message"] == "No refresh token provided"


def test_logout_success():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.create_revoked_token", new=AsyncMock()), \
         patch("app.controllers.auth_controller.read_expiration_date", new=AsyncMock(return_value=123456)):
        cookies = {"refresh_token": "refresh"}
        response = client.post("/auth/logout", headers=headers, cookies=cookies)
        assert response.status_code == 200
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "Logout successful, refresh token revoked"


# --- ACCOUNT EXISTS ---
def test_account_exists_true():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"email": "test@example.com"})):
        response = client.post("/auth/account_exists", json={"email": "test@example.com"})
        assert response.status_code == 200
        assert response.json()["user_exists"] is True
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "User existence check completed"


def test_account_exists_false():
    with patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/auth/account_exists", json={"email": "nouser@example.com"})
        assert response.status_code == 200
        assert response.json()["user_exists"] is False
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "User existence check completed"


# --- CHANGE PASSWORD ---
def test_change_password_user_not_exist():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
        patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value=None)):
        response = client.post("/auth/change_password", json={"email": "nouser@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 400
        assert response.json()["code"] == "user_no_exist"
        assert response.json()["message"] == "User with email nouser@example.com don't exist"


def test_change_password_invalid_old_password():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"email": "test@example.com", "password": "hashed"})), \
         patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=False)):
        response = client.post("/auth/change_password", json={"email": "test@example.com", "old_password": "15pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_old_password"
        assert response.json()["message"] == "Invalid old password"


def test_change_password_success():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.read_user_by_email", new=AsyncMock(return_value={"email": "test@example.com", "password": "hashed"})), \
         patch("app.controllers.auth_controller.verify_password", new=AsyncMock(return_value=True)), \
         patch("app.controllers.auth_controller.get_hashed_password", new=AsyncMock(return_value="new_hashed")), \
         patch("app.controllers.auth_controller.update_user_password", new=AsyncMock()):
        response = client.post("/auth/change_password", json={"email": "test@example.com", "old_password": "13pAssword*", "new_password": "14pAssword*"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "Password changed successfully"


# --- CHECK TOKEN ---
def test_check_token_missing():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/auth/check_token", json={"token": ""}, headers=headers)
        assert response.status_code == 400  
        assert response.json()["code"] == "token_missing"
        assert response.json()["message"] == "No token was provided"


def test_check_token_valid():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.verify_access_token", new=AsyncMock(return_value={"user_id": "abc123"})):
        response = client.post("/auth/check_token", json={"token": "sometoken"}, headers=headers)
        assert response.status_code == 200
        assert response.json()["valid"] is True
        assert response.json()["code"] == "success"
        assert response.json()["message"] == "Token verification completed"


def test_check_token_expired():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
        patch("app.controllers.auth_controller.verify_access_token", new=AsyncMock(side_effect=ExpiredSignatureError)):
        response = client.post("/auth/check_token", json={"token": "expiredtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["code"] == "token_expired"
        assert response.json()["message"] == "The token has expired"


def test_check_token_invalid():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
        patch("app.controllers.auth_controller.verify_access_token", new=AsyncMock(side_effect=InvalidTokenError)):
        response = client.post("/auth/check_token", json={"token": "invalidtoken"}, headers=headers)
        assert response.status_code == 401
        assert response.json()["code"] == "token_invalid"
        assert response.json()["message"] == "The token is invalid"


# --- REFRESH TOKEN ---
def test_refresh_token_missing():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}):
        response = client.post("/auth/refresh_token", headers=headers)
        assert response.status_code == 400
        assert response.json()["code"] == "missing_refresh_token"
        assert response.json()["message"] == "No refresh token provided"


def test_refresh_token_revoked():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.is_token_revoked", new=AsyncMock(return_value=True)):
        cookies = {"refresh_token": "revokedtoken"}
        response = client.post("/auth/refresh_token", cookies=cookies, headers=headers)
        assert response.status_code == 401
        assert response.json()["code"] == "token_revoked"
        assert response.json()["message"] == "The refresh token has been revoked"   

def test_refresh_token_success():
    headers = {"Authorization": "Bearer faketoken"}
    with patch("app.utils.jwt_encoder.verify_access_token", return_value={"user_id": "abc123"}), \
         patch("app.controllers.auth_controller.is_token_revoked", new=AsyncMock(return_value=False)), \
         patch("app.controllers.auth_controller.verify_refresh_token", new=AsyncMock(return_value={"user_id": "1"})), \
         patch("app.controllers.auth_controller.create_access_token", new=AsyncMock(return_value="new_access")):
        cookies = {"refresh_token": "validtoken"}
        response = client.post("/auth/refresh_token", cookies=cookies, headers=headers)
        assert response.status_code == 200
        assert response.json()["code"] == "success"
        assert "access_token" in response.json()
