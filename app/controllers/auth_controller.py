from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import JSONResponse
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.database import DatabaseManager, get_database_manager
from app.limiter import limiter
from app.schemas.auth import (
    AccountExistsRequest,
    ChangePasswordRequest,
    LoginRequest,
    SignUpRequest,
    VerifyTokenRequest,
)
from app.services import AuthService
from app.settings import settings
from app.utils import (
    JSONEncoder,
    JWTBearer,
    PasswordEncoder,
)

router = APIRouter()
jwt_bearer = JWTBearer()
json_encoder = JSONEncoder()
password_encoder = PasswordEncoder()


def get_auth_service(db: DatabaseManager = Depends(get_database_manager)) -> AuthService:
    return AuthService(db)

@router.post(
    "/signup",
    summary="User Signup",
    description="Create a new user account.",
    response_description="User created successfully.",
    tags=["Secure Chain Auth"]
)
@limiter.limit("25/minute")
async def signup(
    request: Request,
    sign_up_request: SignUpRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    existing_user = await auth_service.read_user_by_email(sign_up_request.email)
    if existing_user:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=json_encoder.encode(
                {
                    "detail": "user_already_exists",
                }
            ),
        )
    await auth_service.create_user({
        "email": sign_up_request.email,
        "password": await password_encoder.hash(sign_up_request.password)
    })
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "detail": "signup_success",
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
async def login(
    request: Request,
    login_request: Annotated[LoginRequest, Body()],
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    user = await auth_service.read_user_by_email(login_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "detail": "user_no_exist",
                }
            ),
        )
    hashed_pass = user.password
    if not await password_encoder.verify(login_request.password, hashed_pass):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "detail": "user_incorrect_password",
                }
            ),
        )
    user_id = str(user.id)
    access_token = await jwt_bearer.create_access_token(user_id)
    refresh_token = await jwt_bearer.create_refresh_token(user_id)
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode({
            "user_id": user_id,
            "detail": "login_success",
        }),
    )
    await jwt_bearer.set_auth_cookies(response, access_token, refresh_token)
    return response


@router.post(
    "/logout",
    summary="User Logout",
    description="Log out a user and revoke their refresh token.",
    response_description="Logout successful.",
    tags=["Secure Chain Auth"],
    dependencies=[Depends(jwt_bearer)]
)
@limiter.limit("25/minute")
async def logout(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode({
                "detail": "missing_refresh_token",
            }),
        )
    await auth_service.create_revoked_token(refresh_token, await jwt_bearer.read_expiration_date(refresh_token))
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode({
            "detail": "logout_success",
        }),
    )
    response.delete_cookie("refresh_token")
    response.delete_cookie("access_token")
    return response


@router.post(
    "/account_exists",
    summary="User Account Existence Check",
    description="Check if a user account exists with the given email.",
    response_description="User existence status.",
    tags=["Secure Chain Auth"]
)
@limiter.limit("25/minute")
async def account_exists(
    request: Request,
    account_exists_request: AccountExistsRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    user = await auth_service.read_user_by_email(account_exists_request.email)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "user_exists": True if user else False,
                "detail": "account_exists_success",
            }
        ),
    )


@router.post(
    "/change_password",
    summary="User Change Password",
    description="Change the password for a user.",
    response_description="Password change status.",
    tags=["Secure Chain Auth"],
    dependencies=[Depends(jwt_bearer)]
)
@limiter.limit("25/minute")
async def change_password(
    request: Request,
    change_password_request: ChangePasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    user = await auth_service.read_user_by_email(change_password_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "detail": "user_no_exist",
                }
            ),
        )
    if not await password_encoder.verify(change_password_request.old_password, user.password):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "detail": "user_invalid_old_password",
                }
            ),
        )
    encrypted_password = await password_encoder.hash(change_password_request.new_password)
    user.password = encrypted_password
    await auth_service.update_user_password(user)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "detail": "change_password_success",
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
            content=json_encoder.encode({
                "valid": False,
                "detail": "token_missing",
            }),
        )
    try:
        payload = await jwt_bearer.verify_access_token(token)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json_encoder.encode({
                "valid": True,
                "user_id": payload.get("user_id"),
                "detail": "token_verification_success",
            }),
        )
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "valid": False,
                "detail": "token_expired",
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "valid": False,
                "detail": "token_invalid",
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder.encode({
                "valid": False,
                "detail": "token_error",
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
async def refresh_token_endpoint(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode({
                "detail": "missing_refresh_token",
            }),
        )
    if await auth_service.is_token_revoked(refresh_token):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "detail": "token_revoked",
            }),
        )
    try:
        payload = await jwt_bearer.verify_refresh_token(refresh_token)
        new_access_token = await jwt_bearer.create_access_token(payload["user_id"])
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json_encoder.encode({
                "detail": "refresh_token_success",
            }),
        )
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=settings.SECURE_COOKIES,
            samesite="none" if settings.SECURE_COOKIES else "lax",
            max_age=60 * 15
        )
        return response
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "detail": "token_expired",
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "detail": "token_invalid",
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder.encode({
                "detail": "token_error",
            }),
        )
