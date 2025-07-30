from fastapi import APIRouter

from app.controllers import auth_controller, health_controller

api_router = APIRouter()
api_router.include_router(auth_controller.router, tags=["Secure Chain Auth"])
api_router.include_router(health_controller.router, tags=["Secure Chain Auth Health"])
