from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.constants import ResponseCode, ResponseMessage
from app.database import DatabaseManager, get_database_manager
from app.schemas.auth import CreateApiKeyRequest
from app.services import ApiKeyService
from app.utils import JWTBearer

router = APIRouter()

jwt_bearer = JWTBearer()


def get_apikey_service(db: DatabaseManager = Depends(get_database_manager)) -> ApiKeyService:
    return ApiKeyService(db)


@router.post(
    "/api-keys/create",
    summary="Create API Key",
    description="Create a new API key for a user.",
    response_description="API key creation status.",
    tags=["Secure Chain Auth - API Keys"],
)
async def create_api_key(
    request: CreateApiKeyRequest,
    payload: dict = Depends(jwt_bearer),
    apikey_service: ApiKeyService = Depends(get_apikey_service)
) -> JSONResponse:
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": ResponseCode.USER_NOT_FOUND,
                "message": ResponseMessage.USER_NOT_FOUND
            }
        )

    api_key_response = await apikey_service.create_api_key(
        user_id=user_id,
        name=request.name,
        expires_at=request.expires_at
    )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "code": ResponseCode.API_KEY_CREATED,
            "message": ResponseMessage.API_KEY_CREATED,
            "data": api_key_response
        }
    )


@router.get(
    "/api-keys/list",
    summary="List API Keys",
    description="Retrieve a list of API keys for the authenticated user.",
    response_description="List of API keys.",
    tags=["Secure Chain Auth - API Keys"],
)
async def list_api_keys(
    payload: dict = Depends(jwt_bearer),
    apikey_service: ApiKeyService = Depends(get_apikey_service)
) -> JSONResponse:
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": ResponseCode.USER_NOT_FOUND,
                "message": ResponseMessage.USER_NOT_FOUND
            }
        )

    api_keys = await apikey_service.list_user_api_keys(user_id)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "code": ResponseCode.API_KEY_LIST_SUCCESS,
            "message": ResponseMessage.API_KEY_LIST_SUCCESS,
            "data": api_keys
        }
    )

@router.patch(
    "/api-keys/{key_id}/revoke",
    summary="Revoke API Key",
    description="Revoke an existing API key for a user.",
    response_description="API key revocation status.",
    tags=["Secure Chain Auth - API Keys"],
)
async def revoke_api_key(
    key_id: str,
    payload: dict = Depends(jwt_bearer),
    apikey_service: ApiKeyService = Depends(get_apikey_service)
) -> JSONResponse:
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": ResponseCode.USER_NOT_FOUND,
                "message": ResponseMessage.USER_NOT_FOUND
            }
        )

    success = await apikey_service.revoke_api_key(key_id, user_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": ResponseCode.API_KEY_NOT_FOUND,
                "message": ResponseMessage.API_KEY_NOT_FOUND
            }
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "code": ResponseCode.API_KEY_REVOKED,
            "message": ResponseMessage.API_KEY_REVOKED
        }
    )
