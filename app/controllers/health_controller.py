from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.utils import json_encoder

from main import limiter

router = APIRouter()

@router.get("/health")
@limiter.limit("25/minute")
def health_check():
    return JSONResponse(
        status_code=status.HTTP_200_OK, content=json_encoder({"code": "healthy"})
    )
