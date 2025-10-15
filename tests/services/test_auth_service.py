from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.auth import RevokedToken, User
from app.services.auth_service import AuthService


@pytest.mark.asyncio
async def test_create_user_saves_user_and_creates_graph():
    user_data = {"email": "test@example.com", "password": "13pAssword*"}
    fake_result = MagicMock(id="123")

    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_session = AsyncMock()
    mock_session.run = AsyncMock()

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session

    service = AuthService()
    service._engine = mock_engine
    service._driver = mock_driver

    await service.create_user(user_data)

    mock_engine.save.assert_called_once()
    mock_session.run.assert_called_once()


@pytest.mark.asyncio
async def test_create_revoked_token_saves_token():
    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock()

    service = AuthService()
    service._engine = mock_engine

    await service.create_revoked_token("sometoken", datetime(2030, 1, 1))

    mock_engine.save.assert_called_once()
    args, _ = mock_engine.save.call_args
    assert isinstance(args[0], RevokedToken)
    assert args[0].token == "sometoken"
    assert args[0].expires_at == datetime(2030, 1, 1)


@pytest.mark.asyncio
async def test_read_user_by_email_returns_user():
    fake_user = User(email="test@example.com", password="13pAssword*")

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_user)

    service = AuthService()
    service._engine = mock_engine

    user = await service.read_user_by_email("test@example.com")

    mock_engine.find_one.assert_called_once_with(User, User.email == "test@example.com")
    assert user == fake_user


@pytest.mark.asyncio
async def test_update_user_password_updates_and_saves():
    fake_user_doc = User(email="test@example.com", password="oldpasS1*")

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_user_doc)
    mock_engine.save = AsyncMock()

    service = AuthService()
    service._engine = mock_engine

    await service.update_user_password(User(email="test@example.com", password="newpasS1*"))

    assert fake_user_doc.password == "newpasS1*"
    mock_engine.save.assert_called_once_with(fake_user_doc)


@pytest.mark.asyncio
async def test_update_user_password_user_not_found():
    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)
    mock_engine.save = AsyncMock()

    service = AuthService()
    service._engine = mock_engine

    await service.update_user_password(User(email="notfound@example.com", password="newpass1*"))

    mock_engine.save.assert_not_called()


@pytest.mark.asyncio
async def test_is_token_revoked_true_and_false():
    fake_token = RevokedToken(token="sometoken", expires_at=datetime(2030, 1, 1))

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_token)

    service = AuthService()
    service._engine = mock_engine

    result = await service.is_token_revoked("sometoken")

    mock_engine.find_one.assert_called_once_with(RevokedToken, RevokedToken.token == "sometoken")
    assert result is True

    mock_engine.find_one = AsyncMock(return_value=None)

    result = await service.is_token_revoked("othertoken")

    mock_engine.find_one.assert_called_once_with(RevokedToken, RevokedToken.token == "othertoken")
    assert result is False
