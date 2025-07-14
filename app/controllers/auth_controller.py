from typing import Annotated

from fastapi import APIRouter, Body, Depends, status, Request
from fastapi.responses import JSONResponse
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

from app.models.auth import (
    AccountExistsRequest,
    ChangePasswordRequest,
    LoginRequest,
    User,
    VerifyTokenRequest,
)
from app.services import (
    create_user,
    read_user_by_email,
    update_user_password,
)
from app.utils import (
    JWTBearer,
    create_access_token,
    create_refresh_token,
    get_hashed_password,
    json_encoder,
    verify_access_token,
    verify_refresh_token,
    verify_password,
)

router = APIRouter()

@router.post("/auth/signup")
async def signup(user: User) -> JSONResponse:
    existing_user = await read_user_by_email(user.email)
    if existing_user:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=json_encoder(
                {
                    "code": "user_already_exists",
                    "message": "User with this email already exists."
                }
            ),
        )
    await create_user({
        "email": user.email,
        "password": await get_hashed_password(user.password)
    })
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(
            {
                "code": "success",
                "message": "User created successfully."
            }
        ),
    )


@router.post("/auth/login")
async def login(login_request: Annotated[LoginRequest, Body()]) -> JSONResponse:
    user = await read_user_by_email(login_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder(
                {
                    "code": "user_no_exist",
                    "message": "User with this email does not exist."}
            ),
        )
    hashed_pass = user["password"]
    if not await verify_password(login_request.password, hashed_pass):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder(
                {
                    "code": "Incorrect password",
                    "message": "The password provided is incorrect."
                }
            ),
        )
    access_token = await create_access_token(user["_id"])
    refresh_token = await create_refresh_token(user["_id"])
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({
            "access_token": access_token,
            "user_id": user["_id"],
            "code": "success",
            "message": "Login successful."
        }),
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 7
    )
    return response


@router.post("/auth/account_exists")
async def account_exists(account_exists_request: AccountExistsRequest) -> JSONResponse:
    user = await read_user_by_email(account_exists_request.email)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(
            {
                "user_exists": True if user else False,
                "code": "success",
                "message": "User existence check completed."
            }
        ),
    )


@router.post("/auth/change_password", dependencies=[Depends(JWTBearer())], tags=["auth"])
async def change_password(change_password_request: ChangePasswordRequest) -> JSONResponse:
    user = await read_user_by_email(change_password_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder(
                {
                    "code": "user_no_exist",
                    "message": f"User with email {change_password_request.email} don't exist"
                }
            ),
        )
    if not await verify_password(change_password_request.old_password, user["password"]):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder(
                {
                    "code": "invalid_old_password",
                    "message": "Invalid old password"
                }
            ),
        )
    encrypted_password = await get_hashed_password(change_password_request.new_password)
    user["password"] = encrypted_password
    await update_user_password(user)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(
            {
                "code": "success",
                "message": "Password changed successfully"
            }
        ),
    )


@router.post("/auth/check_token")
async def check_token(verify_token_request: VerifyTokenRequest) -> JSONResponse:
    token = verify_token_request.token
    if not token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder({
                "valid": False,
                "reason": "No token provided",
                "code": "token_missing",
                "message": "No token was provided."
            }),
        )
    try:
        payload = await verify_access_token(token)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json_encoder({
                "valid": True,
                "user_id": payload.get("user_id"),
                "code": "success",
                "message": "Token verification completed."
            }),
        )
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "valid": False,
                "code": "token_expired",
                "message": "The token has expired."
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "valid": False,
                "code": "token_invalid",
                "message": "The token is invalid."
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder({
                "valid": False,
                "code": "token_error",
                "message": "An error occurred during token verification."
            }),
        )


@router.post("/auth/refresh_token")
async def refresh_token_endpoint(request: Request) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder({
                "code": "missing_refresh_token",
                "message": "No refresh token provided."
            }),
        )
    try:
        payload = await verify_refresh_token(refresh_token)
        new_access_token = await create_access_token(payload["user_id"])
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json_encoder({
                "access_token": new_access_token,
                "code": "success",
                "message": "Access token refreshed."
            }),
        )
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "code": "token_expired",
                "message": "The refresh token has expired."
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "code": "token_invalid",
                "message": "The refresh token is invalid."
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder({
                "code": "token_error",
                "message": "An error occurred during refresh token verification."
            }),
        )
