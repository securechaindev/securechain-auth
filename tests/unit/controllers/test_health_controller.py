from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"code": "healthy", "message": "API is running and healthy"}
