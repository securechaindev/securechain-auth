from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.auth import RevokedToken, User
from app.services import auth_service


@pytest.mark.asyncio
async def test_create_user_saves_user_and_creates_graph():
    user_data = {"email": "test@example.com", "password": "13pAssword*"}
    fake_result = MagicMock(id="123")
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(save=AsyncMock(return_value=fake_result))) as mock_get_engine, \
         patch("app.services.auth_service.get_graph_db_driver") as mock_get_driver:
        mock_session = AsyncMock()
        mock_get_driver.return_value.session.return_value.__aenter__.return_value = mock_session
        mock_session.run = AsyncMock()
        await auth_service.create_user(user_data)
        mock_get_engine.return_value.save.assert_called_once()
        mock_session.run.assert_called_once()

@pytest.mark.asyncio
async def test_create_revoked_token_saves_token():
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(save=AsyncMock())) as mock_get_engine:
        await auth_service.create_revoked_token("sometoken", datetime(2030, 1, 1))
        mock_get_engine.return_value.save.assert_called_once()
        args, _ = mock_get_engine.return_value.save.call_args
        assert isinstance(args[0], RevokedToken)
        assert args[0].token == "sometoken"
        assert args[0].expires_at == datetime(2030, 1, 1)

@pytest.mark.asyncio
async def test_read_user_by_email_returns_user():
    fake_user = User(email="test@example.com", password="13pAssword*")
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(find_one=AsyncMock(return_value=fake_user))) as mock_get_engine:
        user = await auth_service.read_user_by_email("test@example.com")
        mock_get_engine.return_value.find_one.assert_called_once_with(User, User.email == "test@example.com")
        assert user == fake_user

@pytest.mark.asyncio
async def test_update_user_password_updates_and_saves():
    fake_user_doc = User(email="test@example.com", password="oldpasS1*")
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(find_one=AsyncMock(return_value=fake_user_doc), save=AsyncMock())) as mock_get_engine:
        await auth_service.update_user_password(User(email="test@example.com", password="newpasS1*"))
        assert fake_user_doc.password == "newpasS1*"
        mock_get_engine.return_value.save.assert_called_once_with(fake_user_doc)

@pytest.mark.asyncio
async def test_update_user_password_user_not_found():
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(find_one=AsyncMock(return_value=None), save=AsyncMock())) as mock_get_engine:
        await auth_service.update_user_password(User(email="notfound@example.com", password="newpass1*"))
        mock_get_engine.return_value.save.assert_not_called()

@pytest.mark.asyncio
async def test_is_token_revoked_true_and_false():
    fake_token = RevokedToken(token="sometoken", expires_at=datetime(2030, 1, 1))
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(find_one=AsyncMock(return_value=fake_token))) as mock_get_engine:
        result = await auth_service.is_token_revoked("sometoken")
        mock_get_engine.return_value.find_one.assert_called_once_with(RevokedToken, RevokedToken.token == "sometoken")
        assert result is True
    with patch("app.services.auth_service.get_odmantic_engine", return_value=AsyncMock(find_one=AsyncMock(return_value=None))) as mock_get_engine:
        result = await auth_service.is_token_revoked("othertoken")
        mock_get_engine.return_value.find_one.assert_called_once_with(RevokedToken, RevokedToken.token == "othertoken")
        assert result is False
