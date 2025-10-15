from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.limiter import limiter
from app.utils import JSONEncoder

router = APIRouter()
json_encoder = JSONEncoder()

@router.get(
    "/health",
    summary="Health Check",
    description="Check the status of the API.",
    response_description="API status.",
    tags=["Secure Chain Auth Health"]
)
@limiter.limit("25/minute")
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK, content= json_encoder.encode(
            {
                "detail": "healthy",
            }
        )
    )
