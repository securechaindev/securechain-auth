from sys import exc_info

from fastapi import Request
from fastapi.exception_handlers import http_exception_handler as _http_exception_handler
from fastapi.exception_handlers import (
    request_validation_exception_handler as _request_validation_exception_handler,
)
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app.logger import logger


async def request_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    body = await request.body()
    query_params = request.query_params._dict
    detail = {
        "code": "validation_error",
        "message": "Validation failed",
        "details": exc.errors(),
        "body": body.decode(),
        "query_params": query_params,
        "path": request.url.path
    }
    logger.info(detail)
    return JSONResponse(status_code=422, content=detail)


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse | Response:
    detail = {
        "code": "http_error",
        "message": exc.detail,
        "details": None,
        "path": request.url.path
    }
    logger.warning(detail)
    return JSONResponse(status_code=exc.status_code, content=detail)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    host = getattr(getattr(request, "client", None), "host", None)
    port = getattr(getattr(request, "client", None), "port", None)
    url = f"{request.url.path}?{request.query_params}" if request.query_params else request.url.path
    exception_type, exception_value, _ = exc_info()
    exception_name = getattr(exception_type, "__name__", None)
    detail = {
        "code": "internal_error",
        "message": str(exception_value),
        "details": exception_name,
        "path": url,
        "client": f"{host}:{port}"
    }
    logger.error(detail)
    return JSONResponse(status_code=500, content=detail)