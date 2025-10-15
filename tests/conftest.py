from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

_mock_engine_patch = patch("app.services.auth_service.get_odmantic_engine")
_mock_driver_patch = patch("app.services.auth_service.get_graph_db_driver")

_mock_engine = _mock_engine_patch.start()
_mock_driver = _mock_driver_patch.start()

_mock_engine.return_value = AsyncMock()
_mock_driver.return_value = MagicMock()


def pytest_sessionfinish(session, exitstatus):
    _mock_engine_patch.stop()
    _mock_driver_patch.stop()


@pytest.fixture(autouse=True)
def reset_auth_service_singleton():
    yield


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c
