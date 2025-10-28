import pytest
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.exception_handler import ExceptionHandler


class ValidationTestModel(BaseModel):
    email: str
    age: int


@pytest.fixture
def app_with_handlers():
    app = FastAPI()

    # Register exception handlers
    app.add_exception_handler(RequestValidationError, ExceptionHandler.request_validation_exception_handler)
    app.add_exception_handler(HTTPException, ExceptionHandler.http_exception_handler)

    @app.post("/test")
    async def test_endpoint(data: ValidationTestModel):
        return {"message": "success"}

    @app.get("/test-http-error")
    async def test_http_error():
        raise HTTPException(status_code=404, detail="not_found")

    return app


def test_request_validation_exception_handler(app_with_handlers):
    client = TestClient(app_with_handlers)

    # Send invalid data to trigger validation error
    response = client.post("/test", json={"email": "invalid", "age": "not-a-number"})

    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "validation_error"


def test_http_exception_handler(app_with_handlers):
    client = TestClient(app_with_handlers)

    response = client.get("/test-http-error")

    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"] == "not_found"
