from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware

from app.exception_handler import (
    http_exception_handler,
    request_validation_exception_handler,
    unhandled_exception_handler,
)
from app.http_session import close_session
from app.middleware import log_request_middleware
from app.router import api_router
from app.limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

DESCRIPTION = """
A simple user registry backend for Secure Chain tools.
"""

@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await close_session()

app = FastAPI(
    title="SecureChain User Backend",
    version="1.0.0",
    description=DESCRIPTION,
    contact={
        "name": "SecureChain Team",
        "url": "https://github.com/securechaindev",
        "email": "hi@securechain.dev",
    },
    license_info={
        "name": "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "url": "https://www.gnu.org/licenses/gpl-3.0.html",
    },
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.middleware("http")(log_request_middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(RequestValidationError, request_validation_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

app.include_router(api_router)
