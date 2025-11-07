class DatabaseConfig:
    MIN_POOL_SIZE = 5
    MAX_POOL_SIZE = 50
    MAX_IDLE_TIME_MS = 60000
    DEFAULT_QUERY_TIMEOUT_MS = 30000

class ResponseCode:
    # Error codes - General
    VALIDATION_ERROR = "validation_error"
    HTTP_ERROR = "http_error"
    INTERNAL_ERROR = "internal_error"
    NOT_AUTHENTICATED = "not_authenticated"

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
    INVALID_TOKEN = "invalid_token"
    TOKEN_ERROR = "token_error"
    TOKEN_REVOKED = "token_revoked"

    # Auth codes - Refresh token
    REFRESH_TOKEN_SUCCESS = "refresh_token_success"

    # API Key codes
    API_KEY_CREATED = "api_key_created"
    API_KEY_LIST_SUCCESS = "api_key_list_success"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_NOT_FOUND = "api_key_not_found"
    API_KEY_NAME_EXISTS = "api_key_name_exists"
    MISSING_API_KEY = "missing_api_key"
    INVALID_API_KEY = "invalid_api_key"
    REVOKED_API_KEY = "revoked_api_key"

    # Health codes
    HEALTHY = "healthy"

class ResponseMessage:
    # Error messages - General
    HTTP_ERROR = "HTTP error"
    INTERNAL_ERROR = "Internal server error"
    NOT_AUTHENTICATED = "Authentication required"

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
    INVALID_TOKEN = "Invalid token"
    TOKEN_ERROR = "An error occurred while verifying the token"
    TOKEN_REVOKED = "The refresh token has been revoked"

    # Auth messages - Refresh token
    REFRESH_TOKEN_SUCCESS = "Access token refreshed successfully"

    # API Key messages
    API_KEY_CREATED = "API key created successfully"
    API_KEY_LIST_SUCCESS = "API keys retrieved successfully"
    API_KEY_REVOKED = "API key revoked successfully"
    API_KEY_NOT_FOUND = "API key not found"
    API_KEY_NAME_EXISTS = "API key with name '{name}' already exists"
    MISSING_API_KEY = "API key is missing"
    INVALID_API_KEY = "Invalid API key"
    REVOKED_API_KEY = "API key has been revoked"

    # Health messages
    HEALTHY = "API is running and healthy"
