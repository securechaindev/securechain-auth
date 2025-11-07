from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId

from app.exceptions import ApiKeyNameExistsException
from app.models.auth import ApiKey
from app.services.api_key_service import ApiKeyService


@pytest.mark.asyncio
async def test_create_api_key_success():
    user_id = "user123"
    name = "Test API Key"
    expires_at = datetime(2030, 12, 31, 23, 59, 59)

    fake_api_key = "test_api_key_12345"
    fake_hash = "hashed_api_key_12345"

    fake_result = MagicMock()
    fake_result.id = ObjectId()
    fake_result.name = name
    fake_result.created_at = datetime(2025, 1, 1, 0, 0, 0)
    fake_result.expires_at = expires_at
    fake_result.is_active = True

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    with patch("app.services.api_key_service.ApiKeyBearer.generate", return_value=fake_api_key), \
         patch("app.services.api_key_service.ApiKeyBearer.hash", return_value=fake_hash):

        result = await service.create_api_key(user_id, name, expires_at)

    assert result["api_key"] == fake_api_key
    assert result["name"] == name
    assert result["is_active"] is True
    assert "id" in result
    assert "created_at" in result
    assert "expires_at" in result

    mock_engine.find_one.assert_called_once()
    mock_engine.save.assert_called_once()

    saved_key = mock_engine.save.call_args[0][0]
    assert isinstance(saved_key, ApiKey)
    assert saved_key.key_hash == fake_hash
    assert saved_key.user_id == user_id
    assert saved_key.name == name


@pytest.mark.asyncio
async def test_create_api_key_duplicate_name():
    user_id = "user123"
    name = "Duplicate Key"
    expires_at = datetime(2030, 12, 31)

    existing_key = MagicMock()

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=existing_key)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    with pytest.raises(ApiKeyNameExistsException) as exc_info:
        await service.create_api_key(user_id, name, expires_at)

    assert name in str(exc_info.value)
    mock_engine.save.assert_not_called()


@pytest.mark.asyncio
async def test_list_user_api_keys_success():
    user_id = "user123"

    key1 = MagicMock()
    key1.id = ObjectId()
    key1.name = "Key 1"
    key1.created_at = datetime(2025, 1, 1)
    key1.expires_at = datetime(2030, 1, 1)
    key1.is_active = True

    key2 = MagicMock()
    key2.id = ObjectId()
    key2.name = "Key 2"
    key2.created_at = datetime(2025, 1, 2)
    key2.expires_at = datetime(2030, 1, 2)
    key2.is_active = False

    key3 = MagicMock()
    key3.id = ObjectId()
    key3.name = "Key 3"
    key3.created_at = datetime(2025, 1, 3)
    key3.expires_at = datetime(2030, 1, 3)
    key3.is_active = True

    fake_keys = [key1, key2, key3]

    mock_engine = AsyncMock()
    mock_engine.find = AsyncMock(return_value=fake_keys)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.list_user_api_keys(user_id)

    assert len(result) == 3
    assert result[0]["name"] == "Key 1"
    assert result[0]["is_active"] is True
    assert result[1]["name"] == "Key 2"
    assert result[1]["is_active"] is False
    assert result[2]["name"] == "Key 3"
    assert result[2]["is_active"] is True

    for key in result:
        assert "id" in key
        assert "name" in key
        assert "created_at" in key
        assert "expires_at" in key
        assert "is_active" in key

    mock_engine.find.assert_called_once()


@pytest.mark.asyncio
async def test_list_user_api_keys_empty():
    user_id = "user_with_no_keys"

    mock_engine = AsyncMock()
    mock_engine.find = AsyncMock(return_value=[])

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.list_user_api_keys(user_id)

    assert len(result) == 0
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_revoke_api_key_success():
    key_id = str(ObjectId())
    user_id = "user123"

    fake_api_key = MagicMock(
        id=ObjectId(key_id),
        user_id=user_id,
        is_active=True
    )

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_api_key)
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, user_id)

    assert result is True
    assert fake_api_key.is_active is False
    mock_engine.find_one.assert_called_once()
    mock_engine.save.assert_called_once_with(fake_api_key)


@pytest.mark.asyncio
async def test_revoke_api_key_not_found():
    key_id = str(ObjectId())
    user_id = "user123"

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, user_id)

    assert result is False
    mock_engine.save.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_api_key_wrong_user():
    key_id = str(ObjectId())
    different_user_id = "user456"

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, different_user_id)

    assert result is False
    mock_engine.save.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_api_key_invalid_object_id():
    invalid_key_id = "not_a_valid_object_id"
    user_id = "user123"

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(side_effect=Exception("Invalid ObjectId"))

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(invalid_key_id, user_id)

    assert result is False


@pytest.mark.asyncio
async def test_api_key_service_initialization():
    mock_engine = MagicMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    assert service.engine == mock_engine
    mock_db.get_odmantic_engine.assert_called_once()


@pytest.mark.asyncio
async def test_create_api_key_with_special_characters_in_name():
    user_id = "user123"
    name = "My-API_Key.v2 (Production)"
    expires_at = datetime(2030, 12, 31)

    fake_api_key = "test_key"
    fake_hash = "hash"

    fake_result = MagicMock()
    fake_result.id = ObjectId()
    fake_result.name = name
    fake_result.created_at = datetime.now()
    fake_result.expires_at = expires_at
    fake_result.is_active = True

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    with patch("app.services.api_key_service.ApiKeyBearer.generate", return_value=fake_api_key), \
         patch("app.services.api_key_service.ApiKeyBearer.hash", return_value=fake_hash):

        result = await service.create_api_key(user_id, name, expires_at)

    assert result["name"] == name


@pytest.mark.asyncio
async def test_create_api_key_with_past_expiration():
    user_id = "user123"
    name = "Expired Key"
    expires_at = datetime(2020, 1, 1)

    fake_api_key = "test_key"
    fake_hash = "hash"

    fake_result = MagicMock()
    fake_result.id = ObjectId()
    fake_result.name = name
    fake_result.created_at = datetime.now()
    fake_result.expires_at = expires_at
    fake_result.is_active = True

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    with patch("app.services.api_key_service.ApiKeyBearer.generate", return_value=fake_api_key), \
         patch("app.services.api_key_service.ApiKeyBearer.hash", return_value=fake_hash):

        result = await service.create_api_key(user_id, name, expires_at)

    assert result["expires_at"] == expires_at.isoformat()


@pytest.mark.asyncio
async def test_revoke_already_revoked_key():
    key_id = str(ObjectId())
    user_id = "user123"

    fake_api_key = MagicMock(
        id=ObjectId(key_id),
        user_id=user_id,
        is_active=False
    )

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_api_key)
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, user_id)

    assert result is True
    assert fake_api_key.is_active is False
    mock_engine.save.assert_called_once()


@pytest.mark.asyncio
async def test_list_user_api_keys_with_mixed_states():
    user_id = "user123"

    key1 = MagicMock()
    key1.id = ObjectId()
    key1.name = "Active Key"
    key1.created_at = datetime(2025, 1, 1)
    key1.expires_at = datetime(2030, 1, 1)
    key1.is_active = True

    key2 = MagicMock()
    key2.id = ObjectId()
    key2.name = "Revoked Key"
    key2.created_at = datetime(2024, 6, 1)
    key2.expires_at = datetime(2029, 6, 1)
    key2.is_active = False

    fake_keys = [key1, key2]

    mock_engine = AsyncMock()
    mock_engine.find = AsyncMock(return_value=fake_keys)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = ApiKeyService(mock_db)

    result = await service.list_user_api_keys(user_id)

    assert len(result) == 2
    active_keys = [k for k in result if k["is_active"]]
    inactive_keys = [k for k in result if not k["is_active"]]
    assert len(active_keys) == 1
    assert len(inactive_keys) == 1
