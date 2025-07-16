import pytest
from pydantic import BaseModel

from app.schemas.auth import SignUpRequest


def test_user_model_fields():
    user = SignUpRequest(email="test@example.com", password="13pAssword*")
    assert hasattr(user, "email")
    assert hasattr(user, "password")
    assert isinstance(user.email, str)
    assert isinstance(user.password, str)


def test_user_model_inheritance():
    user = SignUpRequest(email="test@example.com", password="13pAssword*")
    assert isinstance(user, BaseModel)


@pytest.mark.parametrize(
    "password,should_raise,expected_error",
    [
        ("pAs", True, "between 8 and 20 characters"),
        ("pAs" + "a" * 18, True, "between 8 and 20 characters"),
        ("pass3dddddd*", True, "capital letter"),
        ("passEdddddd*", True, "digit"),
        ("passE3ddddddd", True, "special character"),
        ("13pAssword*", False, None),
    ]
)
def test_user_model_password_validation(password, should_raise, expected_error):
    if should_raise:
        with pytest.raises(ValueError, match=expected_error):
            SignUpRequest(email="test@example.com", password=password)
    else:
        user = SignUpRequest(email="test@example.com", password=password)
        assert user.password == password
