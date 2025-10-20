from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException
from starlette.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import get_database_manager
from app.exception_handler import ExceptionHandler
from app.limiter import limiter
from app.middleware import LogRequestMiddleware
from app.router import api_router

DESCRIPTION = """
A simple user registry backend for Secure Chain tools, built with FastAPI. This service provides user authentication, registration, password management, and token-based security.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager = get_database_manager()
    await db_manager.initialize()
    yield
    await db_manager.close()


app = FastAPI(
    lifespan=lifespan,
    title="Secure Chain User Backend",
    docs_url=settings.DOCS_URL,
    version="1.1.1",
    description=DESCRIPTION,
    contact={
        "name": "Secure Chain Team",
        "url": "https://github.com/securechaindev",
        "email": "hi@securechain.dev",
    },
    license_info={
        "name": "License :: OSI Approved :: Apache Software License",
        "url": "https://www.apache.org/licenses/LICENSE-2.0",
    },
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(LogRequestMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.SERVICES_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(RequestValidationError, ExceptionHandler.request_validation_exception_handler)
app.add_exception_handler(HTTPException, ExceptionHandler.http_exception_handler)
app.add_exception_handler(Exception, ExceptionHandler.unhandled_exception_handler)

app.include_router(api_router)
