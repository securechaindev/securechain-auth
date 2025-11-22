from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from bson import ObjectId

from app.services.user_service import UserService


@pytest.mark.asyncio
async def test_create_user_saves_user_and_creates_graph():
    fake_inserted_id = ObjectId()
    fake_result = MagicMock(inserted_id=fake_inserted_id)

    mock_users_collection = AsyncMock()
    mock_users_collection.insert_one = AsyncMock(return_value=fake_result)

    mock_session = AsyncMock()
    mock_session.run = AsyncMock()

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session

    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = mock_users_collection
    mock_db.get_revoked_tokens_collection.return_value = AsyncMock()
    mock_db.get_neo4j_driver.return_value = mock_driver

    service = UserService(mock_db)

    await service.create_user("test@example.com", "hashed_password")

    mock_users_collection.insert_one.assert_called_once()
    call_args = mock_users_collection.insert_one.call_args[0][0]
    assert call_args["email"] == "test@example.com"
    assert call_args["password"] == "hashed_password"
    mock_session.run.assert_called_once()


@pytest.mark.asyncio
async def test_create_revoked_token_saves_token():
    mock_revoked_tokens_collection = AsyncMock()
    mock_revoked_tokens_collection.insert_one = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = AsyncMock()
    mock_db.get_revoked_tokens_collection.return_value = mock_revoked_tokens_collection
    mock_db.get_neo4j_driver.return_value = MagicMock()

    service = UserService(mock_db)

    test_date = datetime(2030, 1, 1)
    await service.create_revoked_token("sometoken", test_date)

    mock_revoked_tokens_collection.insert_one.assert_called_once()
    call_args = mock_revoked_tokens_collection.insert_one.call_args[0][0]
    assert call_args["token"] == "sometoken"
    assert call_args["expires_at"] == test_date


@pytest.mark.asyncio
async def test_read_user_by_email_returns_user():
    fake_user = {
        "_id": ObjectId(),
        "email": "test@example.com",
        "password": "13pAssword*"
    }

    mock_users_collection = AsyncMock()
    mock_users_collection.find_one = AsyncMock(return_value=fake_user)

    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = mock_users_collection
    mock_db.get_revoked_tokens_collection.return_value = AsyncMock()
    mock_db.get_neo4j_driver.return_value = MagicMock()

    service = UserService(mock_db)

    user = await service.read_user_by_email("test@example.com")

    mock_users_collection.find_one.assert_called_once_with({"email": "test@example.com"})
    assert user == fake_user


@pytest.mark.asyncio
async def test_update_user_password_updates_and_saves():
    mock_users_collection = AsyncMock()
    mock_users_collection.update_one = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = mock_users_collection
    mock_db.get_revoked_tokens_collection.return_value = AsyncMock()
    mock_db.get_neo4j_driver.return_value = MagicMock()

    service = UserService(mock_db)

    await service.update_user_password("test@example.com", "newpasS1*")

    mock_users_collection.update_one.assert_called_once_with(
        {"email": "test@example.com"},
        {"$set": {"password": "newpasS1*"}}
    )


@pytest.mark.asyncio
async def test_update_user_password_user_not_found():
    mock_users_collection = AsyncMock()
    mock_users_collection.update_one = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = mock_users_collection
    mock_db.get_revoked_tokens_collection.return_value = AsyncMock()
    mock_db.get_neo4j_driver.return_value = MagicMock()

    service = UserService(mock_db)

    await service.update_user_password("notfound@example.com", "newpass1*")

    mock_users_collection.update_one.assert_called_once()


@pytest.mark.asyncio
async def test_is_token_revoked_true_and_false():
    fake_token = {
        "token": "sometoken",
        "expires_at": datetime(2030, 1, 1)
    }

    mock_revoked_tokens_collection = AsyncMock()
    mock_revoked_tokens_collection.find_one = AsyncMock(return_value=fake_token)

    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = AsyncMock()
    mock_db.get_revoked_tokens_collection.return_value = mock_revoked_tokens_collection
    mock_db.get_neo4j_driver.return_value = MagicMock()

    service = UserService(mock_db)

    result = await service.is_token_revoked("sometoken")
    assert result is True

    mock_revoked_tokens_collection.find_one = AsyncMock(return_value=None)
    result = await service.is_token_revoked("othertoken")
    assert result is False
