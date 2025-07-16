from app.models.auth import User
from odmantic import Model
import pytest


def test_user_model_fields():
    user = User(email="test@example.com", password="13pAssword*")
    assert hasattr(user, "email")
    assert hasattr(user, "password")
    assert isinstance(user.email, str)
    assert isinstance(user.password, str)


def test_user_model_inheritance():
    user = User(email="test@example.com", password="13pAssword*")
    assert isinstance(user, Model)


@pytest.mark.parametrize(
    "password,should_raise,expected_error",
    [
        ("pAs", True, "between 8 and 20 characters"),
        ("pAs" + "a" * 18, True, "between 8 and 20 characters"),
        ("pass3*dddddd", True, "capital letter"),
        ("passE*dddddd", True, "digit"),
        ("passE3ddddddd", True, "special character"),
        ("13pAssword*", False, None),
    ]
)
def test_user_model_password_validation(password, should_raise, expected_error):
    if should_raise:
        with pytest.raises(ValueError, match=expected_error):
            User(email="test@example.com", password=password)
    else:
        user = User(email="test@example.com", password=password)
        assert user.password == password
