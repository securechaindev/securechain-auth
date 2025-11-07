from fastapi import APIRouter

from app.controllers import api_key_controller, health_controller, user_controller

api_router = APIRouter()
api_router.include_router(user_controller.router, tags=["Secure Chain Auth - User"])
api_router.include_router(api_key_controller.router, tags=["Secure Chain Auth - API Keys"])
api_router.include_router(health_controller.router, tags=["Secure Chain Auth - Health"])
