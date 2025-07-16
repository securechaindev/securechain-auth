from fastapi import APIRouter, status, Request
from fastapi.responses import JSONResponse

from app.utils import json_encoder

from app.limiter import limiter

router = APIRouter()

@router.get(
    "/health",
    summary="Health Check",
    description="Check the status of the API.",
    response_description="API status.",
    tags=["health"]
)
@limiter.limit("25/minute")
def health_check(request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK, content=json_encoder({"code": "healthy"})
    )
