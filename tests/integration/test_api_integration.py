import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint_integration(client):
    """Test that the health endpoint returns OK status."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["code"] == "healthy"
    assert "message" in data


def test_api_returns_json_content_type(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")


def test_nonexistent_endpoint_returns_404(client):
    response = client.get("/nonexistent-endpoint")

    assert response.status_code == 500
