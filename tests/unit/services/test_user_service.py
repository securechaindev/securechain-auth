from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.auth import RevokedToken, User
from app.services.user_service import UserService


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

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine
    mock_db.get_neo4j_driver.return_value = mock_driver

    service = UserService(mock_db)

    await service.create_user(user_data)

    mock_engine.save.assert_called_once()
    mock_session.run.assert_called_once()


@pytest.mark.asyncio
async def test_create_revoked_token_saves_token():
    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

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

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    user = await service.read_user_by_email("test@example.com")

    mock_engine.find_one.assert_called_once_with(User, User.email == "test@example.com")
    assert user == fake_user


@pytest.mark.asyncio
async def test_update_user_password_updates_and_saves():
    fake_user_doc = User(email="test@example.com", password="oldpasS1*")

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_user_doc)
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    await service.update_user_password(User(email="test@example.com", password="newpasS1*"))

    assert fake_user_doc.password == "newpasS1*"
    mock_engine.save.assert_called_once_with(fake_user_doc)


@pytest.mark.asyncio
async def test_update_user_password_user_not_found():
    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    await service.update_user_password(User(email="notfound@example.com", password="newpass1*"))

    mock_engine.save.assert_not_called()


@pytest.mark.asyncio
async def test_is_token_revoked_true_and_false():
    fake_token = RevokedToken(token="sometoken", expires_at=datetime(2030, 1, 1))

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_token)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    result = await service.is_token_revoked("sometoken")

    mock_engine.find_one.assert_called_once_with(RevokedToken, RevokedToken.token == "sometoken")
    assert result is True

    mock_engine.find_one = AsyncMock(return_value=None)

    result = await service.is_token_revoked("othertoken")

    mock_engine.find_one.assert_called_once_with(RevokedToken, RevokedToken.token == "othertoken")
    assert result is False

@pytest.mark.asyncio
async def test_create_user_with_complex_email():
    user_data = {"email": "complex.email+tag@subdomain.example.com", "password": "C0mpl3x*Pass"}
    fake_result = MagicMock(id="456")

    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_session = AsyncMock()
    mock_session.run = AsyncMock()

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine
    mock_db.get_neo4j_driver.return_value = mock_driver

    service = UserService(mock_db)

    await service.create_user(user_data)

    call_args = mock_engine.save.call_args
    saved_user = call_args[0][0]
    assert saved_user.email == "complex.email+tag@subdomain.example.com"
    assert saved_user.password == "C0mpl3x*Pass"


@pytest.mark.asyncio
async def test_create_user_graph_node_with_correct_id():
    user_data = {"email": "graph@example.com", "password": "Gr4ph*Pass"}
    fake_result = MagicMock(id="neo4j-user-123")

    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_session = AsyncMock()
    mock_session.run = AsyncMock()

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine
    mock_db.get_neo4j_driver.return_value = mock_driver

    service = UserService(mock_db)

    await service.create_user(user_data)

    mock_session.run.assert_called_once()
    call_kwargs = mock_session.run.call_args[1]
    assert call_kwargs["user_id"] == "neo4j-user-123"


@pytest.mark.asyncio
async def test_read_user_by_email_with_nonexistent_email():
    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    user = await service.read_user_by_email("nonexistent@example.com")

    mock_engine.find_one.assert_called_once_with(User, User.email == "nonexistent@example.com")
    assert user is None


@pytest.mark.asyncio
async def test_create_revoked_token_with_past_expiration():
    past_date = datetime(2020, 1, 1, 12, 0, 0)

    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    await service.create_revoked_token("expired_token", past_date)

    mock_engine.save.assert_called_once()
    args, _ = mock_engine.save.call_args
    revoked_token = args[0]
    assert isinstance(revoked_token, RevokedToken)
    assert revoked_token.token == "expired_token"
    assert revoked_token.expires_at == past_date


@pytest.mark.asyncio
async def test_create_multiple_revoked_tokens():
    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    tokens = [
        ("token1", datetime(2030, 1, 1)),
        ("token2", datetime(2030, 2, 1)),
        ("token3", datetime(2030, 3, 1)),
    ]

    for token, expires_at in tokens:
        await service.create_revoked_token(token, expires_at)

    assert mock_engine.save.call_count == 3


@pytest.mark.asyncio
async def test_update_user_password_maintains_email():
    original_user = User(email="maintain@example.com", password="0ldPa55*")

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=original_user)
    mock_engine.save = AsyncMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    updated_user = User(email="maintain@example.com", password="N3wPa55*")
    await service.update_user_password(updated_user)

    assert original_user.email == "maintain@example.com"
    assert original_user.password == "N3wPa55*"
    mock_engine.save.assert_called_once_with(original_user)


@pytest.mark.asyncio
async def test_is_token_revoked_with_empty_token():
    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=None)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    result = await service.is_token_revoked("")

    assert result is False
    mock_engine.find_one.assert_called_once()


@pytest.mark.asyncio
async def test_user_service_initialization():
    mock_engine = MagicMock()
    mock_driver = MagicMock()

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine
    mock_db.get_neo4j_driver.return_value = mock_driver

    service = UserService(mock_db)

    assert service.driver == mock_driver
    assert service.engine == mock_engine
    mock_db.get_odmantic_engine.assert_called_once()
    mock_db.get_neo4j_driver.assert_called_once()


@pytest.mark.asyncio
async def test_read_user_by_email_case_sensitivity():
    fake_user = User(email="test@example.com", password="T3st*Pass")

    mock_engine = AsyncMock()
    mock_engine.find_one = AsyncMock(return_value=fake_user)

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    service = UserService(mock_db)

    user = await service.read_user_by_email("test@example.com")

    assert user is not None
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_create_user_verifies_user_model_instance():
    user_data = {"email": "model@example.com", "password": "M0d3l*Pass"}
    fake_result = MagicMock(id="model-123")

    mock_engine = AsyncMock()
    mock_engine.save = AsyncMock(return_value=fake_result)

    mock_session = AsyncMock()
    mock_session.run = AsyncMock()

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session

    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine
    mock_db.get_neo4j_driver.return_value = mock_driver

    service = UserService(mock_db)

    await service.create_user(user_data)

    call_args = mock_engine.save.call_args
    saved_user = call_args[0][0]
    assert isinstance(saved_user, User)
    assert hasattr(saved_user, 'email')
    assert hasattr(saved_user, 'password')
