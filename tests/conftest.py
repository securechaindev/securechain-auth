# tests/conftest.py
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    with patch("app.services.dbs.databases.get_odmantic_engine") as mock_get_engine:
        mock_get_engine.return_value = MagicMock()
        from app.main import app  # Importa después de aplicar el patch
        with TestClient(app) as c:
            yield c
