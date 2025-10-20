from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.controllers.auth_controller import get_auth_service
from app.database import get_database_manager


@pytest.fixture(scope="session")
def mock_db_manager():
    mock_db = MagicMock()

    mock_engine = AsyncMock()
    mock_db.get_odmantic_engine.return_value = mock_engine

    mock_driver = MagicMock()
    mock_session = AsyncMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    mock_db.get_neo4j_driver.return_value = mock_driver

    mock_db.initialize = AsyncMock()
    mock_db.close = AsyncMock()

    return mock_db


@pytest.fixture(scope="session")
def mock_auth_service():
    mock_auth = MagicMock()
    mock_auth.read_user_by_email = AsyncMock()
    mock_auth.create_user = AsyncMock()
    mock_auth.create_revoked_token = AsyncMock()
    mock_auth.update_user_password = AsyncMock()
    mock_auth.is_token_revoked = AsyncMock()
    return mock_auth


@pytest.fixture(scope="session")
def mock_jwt_bearer():
    class MockJWTBearer:
        async def __call__(self, request):
            return {"user_id": "abc123"}

    return MockJWTBearer()


@pytest.fixture(scope="function")
def client(mock_db_manager, mock_auth_service, mock_jwt_bearer):
    from app.controllers.auth_controller import jwt_bearer
    from app.main import app

    @asynccontextmanager
    async def test_lifespan(app):
        yield

    app.router.lifespan_context = test_lifespan

    app.dependency_overrides[get_database_manager] = lambda: mock_db_manager
    app.dependency_overrides[get_auth_service] = lambda: mock_auth_service
    app.dependency_overrides[jwt_bearer] = lambda: mock_jwt_bearer

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()

