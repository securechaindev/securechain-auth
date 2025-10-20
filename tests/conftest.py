from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

_mock_db_manager_patch = patch("app.database.DatabaseManager")

_mock_db_manager_class = _mock_db_manager_patch.start()
_mock_db_manager = MagicMock()
_mock_db_manager_class.return_value = _mock_db_manager

_mock_db_manager.get_odmantic_engine.return_value = AsyncMock()
_mock_db_manager.get_neo4j_driver.return_value = MagicMock()
_mock_db_manager.initialize = AsyncMock()
_mock_db_manager.close = AsyncMock()


def pytest_sessionfinish(session, exitstatus):
    _mock_db_manager_patch.stop()


@pytest.fixture(autouse=True)
def reset_auth_service_singleton():
    yield


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c
