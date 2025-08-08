from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import JSONResponse
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.limiter import limiter
from app.schemas.auth import (
    AccountExistsRequest,
    ChangePasswordRequest,
    LoginRequest,
    SignUpRequest,
    VerifyTokenRequest,
)
from app.services import (
    create_revoked_token,
    create_user,
    is_token_revoked,
    read_user_by_email,
    update_user_password,
)
from app.config import settings
from app.utils import (
    JWTBearer,
    create_access_token,
    create_refresh_token,
    get_hashed_password,
    json_encoder,
    read_expiration_date,
    verify_access_token,
    verify_password,
    verify_refresh_token,
)

router = APIRouter()

@router.post(
    "/signup",
    summary="User Signup",
    description="Create a new user account.",
    response_description="User created successfully.",
    tags=["Secure Chain Auth"]
)
@limiter.limit("25/minute")
async def signup(request: Request, sign_up_request: SignUpRequest) -> JSONResponse:
    existing_user = await read_user_by_email(sign_up_request.email)
    if existing_user:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=json_encoder(
                {
                    "code": "user_already_exists",
                    "message": "User with this email already exists"
                }
            ),
        )
    await create_user({
        "email": sign_up_request.email,
        "password": await get_hashed_password(sign_up_request.password)
    })
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(
            {
                "code": "success",
                "message": "User created successfully"
            }
        ),
    )


@router.post(
    "/login",
    summary="User Login",
    description="Authenticate a user with email and password.",
    response_description="Access token and user data.",
    tags=["Secure Chain Auth"]
)
@limiter.limit("25/minute")
async def login(request: Request, login_request: Annotated[LoginRequest, Body()]) -> JSONResponse:
    user = await read_user_by_email(login_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder(
                {
                    "code": "user_no_exist",
                    "message": "User with this email does not exist"}
            ),
        )
    hashed_pass = user.password
    if not await verify_password(login_request.password, hashed_pass):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder(
                {
                    "code": "Incorrect password",
                    "message": "The password provided is incorrect"
                }
            ),
        )
    user_id = str(user.id)
    access_token = await create_access_token(user_id)
    refresh_token = await create_refresh_token(user_id)
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({
            "access_token": access_token,
            "user_id": user_id,
            "code": "success",
            "message": "Login successful"
        }),
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.SECURE,
        samesite="none" if settings.SECURE else "lax",
        max_age=60 * 15
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.SECURE,
        samesite="none" if settings.SECURE else "lax",
        max_age=60 * 60 * 24 * 7
    )
    return response


@router.post(
    "/logout",
    summary="User Logout",
    description="Log out a user and revoke their refresh token.",
    response_description="Logout successful.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain Auth"]
)
@limiter.limit("25/minute")
async def logout(request: Request) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder({
                "code": "missing_refresh_token",
                "message": "No refresh token provided"
            }),
        )
    await create_revoked_token(refresh_token, await read_expiration_date(refresh_token))
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({
            "code": "success",
            "message": "Logout successful, refresh token revoked"
        }),
    )
    response.delete_cookie("refresh_token")
    return response


@router.post(
    "/account_exists",
    summary="User Account Existence Check",
    description="Check if a user account exists with the given email.",
    response_description="User existence status.",
    tags=["Secure Chain Auth"]
)
@limiter.limit("25/minute")
async def account_exists(request: Request, account_exists_request: AccountExistsRequest) -> JSONResponse:
    user = await read_user_by_email(account_exists_request.email)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(
            {
                "user_exists": True if user else False,
                "code": "success",
                "message": "User existence check completed"
            }
        ),
    )


@router.post(
    "/change_password",
    summary="User Change Password",
    description="Change the password for a user.",
    response_description="Password change status.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain Auth"],
)
@limiter.limit("25/minute")
async def change_password(request: Request, change_password_request: ChangePasswordRequest) -> JSONResponse:
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
    if not await verify_password(change_password_request.old_password, user.password):
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
    user.password = encrypted_password
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


@router.post(
    "/check_token",
    summary="User Token Verification",
    description="Verify the validity of a user token.",
    response_description="Token verification status.",
    tags=["Secure Chain Auth"],
)
@limiter.limit("25/minute")
async def check_token(request: Request, verify_token_request: VerifyTokenRequest) -> JSONResponse:
    token = verify_token_request.token
    if not token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder({
                "valid": False,
                "code": "token_missing",
                "message": "No token was provided"
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
                "message": "Token verification completed"
            }),
        )
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "valid": False,
                "code": "token_expired",
                "message": "The token has expired"
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "valid": False,
                "code": "token_invalid",
                "message": "The token is invalid"
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder({
                "valid": False,
                "code": "token_error",
                "message": "An error occurred during token verification"
            }),
        )


@router.post(
    "/refresh_token",
    summary="User Refresh Token",
    description="Refresh a user's access token using a refresh token.",
    response_description="New access token.",
    tags=["Secure Chain Auth"],
)
@limiter.limit("25/minute")
async def refresh_token_endpoint(request: Request) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder({
                "code": "missing_refresh_token",
                "message": "No refresh token provided"
            }),
        )
    if await is_token_revoked(refresh_token):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "code": "token_revoked",
                "message": "The refresh token has been revoked"
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
                "message": "Access token refreshed"
            }),
        )
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "code": "token_expired",
                "message": "The refresh token has expired"
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder({
                "code": "token_invalid",
                "message": "The refresh token is invalid"
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder({
                "code": "token_error",
                "message": "An error occurred during refresh token verification"
            }),
        )
