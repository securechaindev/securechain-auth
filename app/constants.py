class DatabaseConfig:
    MIN_POOL_SIZE = 5
    MAX_POOL_SIZE = 50
    MAX_IDLE_TIME_MS = 60000
    DEFAULT_QUERY_TIMEOUT_MS = 30000

    USERS_COLLECTION = "users"
    REVOKED_TOKENS_COLLECTION = "revoked_tokens"

class ResponseCode:
    # Error codes - General
    VALIDATION_ERROR = "validation_error"
    HTTP_ERROR = "http_error"
    INTERNAL_ERROR = "internal_error"

    # Auth codes - Signup
    SIGNUP_SUCCESS = "signup_success"
    USER_ALREADY_EXISTS = "user_already_exists"

    # Auth codes - Login
    LOGIN_SUCCESS = "login_success"
    USER_NOT_FOUND = "user_not_found"
    INCORRECT_PASSWORD = "incorrect_password"

    # Auth codes - Logout
    LOGOUT_SUCCESS = "logout_success"
    MISSING_REFRESH_TOKEN = "missing_refresh_token"

    # Auth codes - Account exists
    ACCOUNT_EXISTS_SUCCESS = "account_exists_success"

    # Auth codes - Change password
    CHANGE_PASSWORD_SUCCESS = "change_password_success"
    INVALID_OLD_PASSWORD = "invalid_old_password"

    # Auth codes - Token validation
    TOKEN_VALID = "token_valid"
    TOKEN_MISSING = "token_missing"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_INVALID = "token_invalid"
    TOKEN_ERROR = "token_error"
    TOKEN_REVOKED = "token_revoked"

    # Auth codes - Refresh token
    REFRESH_TOKEN_SUCCESS = "refresh_token_success"

    # Health codes
    HEALTHY = "healthy"

class ResponseMessage:
    # Error messages - General
    VALIDATION_ERROR = "Validation error"
    HTTP_ERROR = "HTTP error"
    INTERNAL_ERROR = "Internal server error"

    # Auth messages - Signup
    SIGNUP_SUCCESS = "User account created successfully"
    USER_ALREADY_EXISTS = "A user with this email already exists"

    # Auth messages - Login
    LOGIN_SUCCESS = "Successfully logged in"
    USER_NOT_FOUND = "No user found with this email address"
    INCORRECT_PASSWORD = "The password provided is incorrect"

    # Auth messages - Logout
    LOGOUT_SUCCESS = "Successfully logged out"
    MISSING_REFRESH_TOKEN = "Refresh token is missing from request"

    # Auth messages - Account exists
    ACCOUNT_EXISTS_SUCCESS = "Account existence check completed successfully"

    # Auth messages - Change password
    CHANGE_PASSWORD_SUCCESS = "Password changed successfully"
    INVALID_OLD_PASSWORD = "The old password provided is incorrect"

    # Auth messages - Token validation
    TOKEN_VALID = "Token is valid"
    TOKEN_MISSING = "Token is missing from request"
    TOKEN_EXPIRED = "Token has expired"
    TOKEN_INVALID = "Token is invalid"
    TOKEN_ERROR = "An error occurred while verifying the token"
    TOKEN_REVOKED = "The refresh token has been revoked"

    # Auth messages - Refresh token
    REFRESH_TOKEN_SUCCESS = "Access token refreshed successfully"

    # Health messages
    HEALTHY = "API is running and healthy"
