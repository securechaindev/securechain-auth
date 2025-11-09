from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import JSONResponse
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.constants import ResponseCode, ResponseMessage
from app.database import DatabaseManager, get_database_manager
from app.limiter import limiter
from app.schemas.auth import (
    AccountExistsRequest,
    ChangePasswordRequest,
    LoginRequest,
    SignUpRequest,
    VerifyTokenRequest,
)
from app.services import UserService
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


def get_user_service(db: DatabaseManager = Depends(get_database_manager)) -> UserService:
    return UserService(db)

@router.post(
    "/user/signup",
    summary="User Signup",
    description="Create a new user account.",
    response_description="User created successfully.",
    tags=["Secure Chain Auth - User"],
)
@limiter.limit("25/minute")
async def signup(
    request: Request,
    sign_up_request: SignUpRequest,
    user_service: UserService = Depends(get_user_service),
) -> JSONResponse:
    existing_user = await user_service.read_user_by_email(sign_up_request.email)
    if existing_user:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=json_encoder.encode(
                {
                    "code": ResponseCode.USER_ALREADY_EXISTS,
                    "message": ResponseMessage.USER_ALREADY_EXISTS,
                }
            ),
        )
    await user_service.create_user({
        "email": sign_up_request.email,
        "password": password_encoder.hash(sign_up_request.password)
    })
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "code": ResponseCode.SIGNUP_SUCCESS,
                "message": ResponseMessage.SIGNUP_SUCCESS,
            }
        ),
    )


@router.post(
    "/user/login",
    summary="User Login",
    description="Authenticate a user with email and password.",
    response_description="Access token and user data.",
    tags=["Secure Chain Auth - User"],
)
@limiter.limit("25/minute")
async def login(
    request: Request,
    login_request: Annotated[LoginRequest, Body()],
    user_service: UserService = Depends(get_user_service),
) -> JSONResponse:
    user = await user_service.read_user_by_email(login_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "code": ResponseCode.USER_NOT_FOUND,
                    "message": ResponseMessage.USER_NOT_FOUND,
                }
            ),
        )
    hashed_pass = user.password
    if not password_encoder.verify(login_request.password, hashed_pass):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "code": ResponseCode.INCORRECT_PASSWORD,
                    "message": ResponseMessage.INCORRECT_PASSWORD,
                }
            ),
        )
    user_id = str(user.id)
    access_token = jwt_bearer.create_access_token(user_id)
    refresh_token = jwt_bearer.create_refresh_token(user_id)
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode({
            "code": ResponseCode.LOGIN_SUCCESS,
            "message": ResponseMessage.LOGIN_SUCCESS,
        }),
    )
    jwt_bearer.set_auth_cookies(response, access_token, refresh_token)
    return response


@router.post(
    "/user/logout",
    summary="User Logout",
    description="Log out a user and revoke their refresh token.",
    response_description="Logout successful.",
    tags=["Secure Chain Auth - User"],
    dependencies=[Depends(jwt_bearer)],
)
@limiter.limit("25/minute")
async def logout(
    request: Request,
    user_service: UserService = Depends(get_user_service),
) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode({
                "code": ResponseCode.MISSING_REFRESH_TOKEN,
                "message": ResponseMessage.MISSING_REFRESH_TOKEN,
            }),
        )
    await user_service.create_revoked_token(refresh_token, jwt_bearer.read_expiration_date(refresh_token))
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode({
            "code": ResponseCode.LOGOUT_SUCCESS,
            "message": ResponseMessage.LOGOUT_SUCCESS,
        }),
    )
    response.delete_cookie("refresh_token")
    response.delete_cookie("access_token")
    return response


@router.post(
    "/user/account_exists",
    summary="User Account Existence Check",
    description="Check if a user account exists with the given email.",
    response_description="User existence status.",
    tags=["Secure Chain Auth - User"],
)
@limiter.limit("25/minute")
async def account_exists(
    request: Request,
    account_exists_request: AccountExistsRequest,
    user_service: UserService = Depends(get_user_service),
) -> JSONResponse:
    user = await user_service.read_user_by_email(account_exists_request.email)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "user_exists": True if user else False,
                "code": ResponseCode.ACCOUNT_EXISTS_SUCCESS,
                "message": ResponseMessage.ACCOUNT_EXISTS_SUCCESS,
            }
        ),
    )


@router.post(
    "/user/change_password",
    summary="User Change Password",
    description="Change the password for a user.",
    response_description="Password change status.",
    tags=["Secure Chain Auth - User"],
    dependencies=[Depends(jwt_bearer)],
)
@limiter.limit("25/minute")
async def change_password(
    request: Request,
    change_password_request: ChangePasswordRequest,
    user_service: UserService = Depends(get_user_service),
) -> JSONResponse:
    user = await user_service.read_user_by_email(change_password_request.email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "code": ResponseCode.USER_NOT_FOUND,
                    "message": ResponseMessage.USER_NOT_FOUND,
                }
            ),
        )
    if not password_encoder.verify(change_password_request.old_password, user.password):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode(
                {
                    "code": ResponseCode.INVALID_OLD_PASSWORD,
                    "message": ResponseMessage.INVALID_OLD_PASSWORD,
                }
            ),
        )
    encrypted_password = password_encoder.hash(change_password_request.new_password)
    user.password = encrypted_password
    await user_service.update_user_password(user)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "code": ResponseCode.CHANGE_PASSWORD_SUCCESS,
                "message": ResponseMessage.CHANGE_PASSWORD_SUCCESS,
            }
        ),
    )


@router.post(
    "/user/check_token",
    summary="User Token Verification",
    description="Verify the validity of a user token.",
    response_description="Token verification status.",
    tags=["Secure Chain Auth - User"],
)
@limiter.limit("25/minute")
async def check_token(request: Request, verify_token_request: VerifyTokenRequest) -> JSONResponse:
    token = verify_token_request.token
    if not token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode({
                "valid": False,
                "code": ResponseCode.TOKEN_MISSING,
                "message": ResponseMessage.TOKEN_MISSING,
            }),
        )
    try:
        jwt_bearer.verify_access_token(token)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json_encoder.encode({
                "valid": True,
                "code": ResponseCode.TOKEN_VALID,
                "message": ResponseMessage.TOKEN_VALID,
            }),
        )
    except ExpiredSignatureError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "valid": False,
                "code": ResponseCode.TOKEN_EXPIRED,
                "message": ResponseMessage.TOKEN_EXPIRED,
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "valid": False,
                "code": ResponseCode.TOKEN_INVALID,
                "message": ResponseMessage.TOKEN_INVALID,
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder.encode({
                "valid": False,
                "code": ResponseCode.TOKEN_ERROR,
                "message": ResponseMessage.TOKEN_ERROR,
            }),
        )


@router.post(
    "/user/refresh_token",
    summary="User Refresh Token",
    description="Refresh a user's access token using a refresh token.",
    response_description="New access token.",
    tags=["Secure Chain Auth - User"],
)
@limiter.limit("25/minute")
async def refresh_token_endpoint(
    request: Request,
    user_service: UserService = Depends(get_user_service),
) -> JSONResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=json_encoder.encode({
                "code": ResponseCode.MISSING_REFRESH_TOKEN,
                "message": ResponseMessage.MISSING_REFRESH_TOKEN,
            }),
        )
    if await user_service.is_token_revoked(refresh_token):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "code": ResponseCode.TOKEN_REVOKED,
                "message": ResponseMessage.TOKEN_REVOKED,
            }),
        )
    try:
        payload = jwt_bearer.verify_refresh_token(refresh_token)
        new_access_token = jwt_bearer.create_access_token(payload.get("user_id"))
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content=json_encoder.encode({
                "code": ResponseCode.REFRESH_TOKEN_SUCCESS,
                "message": ResponseMessage.REFRESH_TOKEN_SUCCESS,
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
                "code": ResponseCode.TOKEN_EXPIRED,
                "message": ResponseMessage.TOKEN_EXPIRED,
            }),
        )
    except InvalidTokenError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=json_encoder.encode({
                "code": ResponseCode.TOKEN_INVALID,
                "message": ResponseMessage.TOKEN_INVALID,
            }),
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=json_encoder.encode({
                "code": ResponseCode.TOKEN_ERROR,
                "message": ResponseMessage.TOKEN_ERROR,
            }),
        )
