from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId

from app.exceptions import ApiKeyNameExistsException
from app.services.api_key_service import ApiKeyService


@pytest.mark.asyncio
async def test_create_api_key_success():
    user_id = "user123"
    name = "Test API Key"
    expires_at = datetime(2030, 12, 31, 23, 59, 59)

    fake_api_key = "sk_test_key"
    fake_hash = "hashed_key"
    fake_inserted_id = ObjectId()
    fake_result = MagicMock(inserted_id=fake_inserted_id)

    mock_collection = AsyncMock()
    mock_collection.find_one = AsyncMock(return_value=None)
    mock_collection.insert_one = AsyncMock(return_value=fake_result)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

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

    mock_collection.find_one.assert_called_once()
    mock_collection.insert_one.assert_called_once()


@pytest.mark.asyncio
async def test_create_api_key_duplicate_name():
    user_id = "user123"
    name = "Duplicate Key"
    expires_at = datetime(2030, 12, 31)

    existing_key = {
        "_id": ObjectId(),
        "user_id": user_id,
        "name": name,
        "key_hash": "existing_hash",
        "created_at": datetime(2025, 1, 1),
        "expires_at": expires_at,
        "is_active": True
    }

    mock_collection = AsyncMock()
    mock_collection.find_one = AsyncMock(return_value=existing_key)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    with pytest.raises(ApiKeyNameExistsException):
        await service.create_api_key(user_id, name, expires_at)

    mock_collection.find_one.assert_called_once_with({"user_id": user_id, "name": name})


@pytest.mark.asyncio
async def test_list_user_api_keys_success():
    user_id = "user123"

    fake_keys = [
        {
            "_id": ObjectId(),
            "name": "Key 1",
            "created_at": datetime(2025, 1, 1),
            "expires_at": datetime(2030, 1, 1),
            "is_active": True
        },
        {
            "_id": ObjectId(),
            "name": "Key 2",
            "created_at": datetime(2025, 2, 1),
            "expires_at": datetime(2030, 2, 1),
            "is_active": False
        }
    ]

    mock_cursor = AsyncMock()
    mock_cursor.to_list = AsyncMock(return_value=fake_keys)

    mock_collection = AsyncMock()
    mock_collection.find = MagicMock(return_value=mock_cursor)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    result = await service.list_user_api_keys(user_id)

    assert len(result) == 2
    assert result[0]["name"] == "Key 1"
    assert result[0]["is_active"] is True
    assert result[1]["name"] == "Key 2"
    assert result[1]["is_active"] is False

    mock_collection.find.assert_called_once_with({"user_id": user_id})


@pytest.mark.asyncio
async def test_list_user_api_keys_empty():
    user_id = "user123"

    mock_cursor = AsyncMock()
    mock_cursor.to_list = AsyncMock(return_value=[])

    mock_collection = AsyncMock()
    mock_collection.find = MagicMock(return_value=mock_cursor)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    result = await service.list_user_api_keys(user_id)

    assert len(result) == 0


@pytest.mark.asyncio
async def test_revoke_api_key_success():
    key_id = str(ObjectId())
    user_id = "user123"

    mock_result = MagicMock(modified_count=1)

    mock_collection = AsyncMock()
    mock_collection.update_one = AsyncMock(return_value=mock_result)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, user_id)

    assert result is True
    mock_collection.update_one.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_api_key_not_found():
    key_id = str(ObjectId())
    user_id = "user123"

    mock_result = MagicMock(modified_count=0)

    mock_collection = AsyncMock()
    mock_collection.update_one = AsyncMock(return_value=mock_result)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, user_id)

    assert result is False


@pytest.mark.asyncio
async def test_revoke_api_key_wrong_user():
    key_id = str(ObjectId())
    wrong_user_id = "user456"

    mock_result = MagicMock(modified_count=0)

    mock_collection = AsyncMock()
    mock_collection.update_one = AsyncMock(return_value=mock_result)

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, wrong_user_id)

    assert result is False


@pytest.mark.asyncio
async def test_revoke_api_key_invalid_object_id():
    key_id = "invalid_id"
    user_id = "user123"

    mock_collection = AsyncMock()
    mock_collection.update_one = AsyncMock(side_effect=Exception("Invalid ObjectId"))

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    result = await service.revoke_api_key(key_id, user_id)

    assert result is False


@pytest.mark.asyncio
async def test_api_key_service_initialization():
    mock_collection = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_api_keys_collection.return_value = mock_collection

    service = ApiKeyService(mock_db)

    assert service.api_keys_collection == mock_collection
