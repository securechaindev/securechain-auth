# SecureChain Auth - Project Context

> **Context file for AI agents**: This document provides a complete overview of the project to facilitate work in new sessions.

## 📋 General Information

- **Project Name**: securechain-auth
- **Version**: 1.0.19
- **Description**: Authentication and user registration backend for Secure Chain tools
- **Framework**: FastAPI 0.116.1
- **Python**: 3.13+
- **License**: GPL-3.0
- **Repository**: https://github.com/securechaindev/login_backend

## 🏗️ Project Architecture

### Directory Structure

```
securechain-auth/
├── app/                          # Main source code
│   ├── main.py                   # FastAPI entry point
│   ├── config.py                 # Configuration using pydantic-settings
│   ├── router.py                 # Main API router
│   ├── middleware.py             # Logging and CORS middleware
│   ├── limiter.py                # Rate limiting with slowapi
│   ├── exception_handler.py      # Exception handling
│   ├── http_session.py           # Shared HTTP session
│   ├── logger.py                 # Logging configuration
│   ├── controllers/              # Endpoint controllers
│   │   ├── auth_controller.py    # Authentication and registration
│   │   └── health_controller.py  # Health checks
│   ├── services/                 # Business logic
│   │   └── auth_service.py       # Authentication service
│   ├── database_manager.py       # Database connection manager (Singleton)
│   ├── constants.py              # Application constants and configurations
│   ├── models/                   # Data models (ODM/OGM)
│   │   └── auth/
│   │       ├── User.py           # User model
│   │       └── RevokedToken.py   # Revoked tokens
│   ├── schemas/                  # Pydantic schemas for validation
│   │   ├── auth/                 # Authentication schemas
│   │   ├── patterns/             # Regex patterns for validation
│   │   └── validators/           # Custom validators
│   ├── utils/                    # Utilities
│   │   ├── jwt_encoder.py        # JWT encoding/decoding (JWTBearer class)
│   │   ├── password_encoder.py   # Password hashing (PasswordEncoder class)
│   │   └── json_encoder.py       # Custom JSON encoder (JSONEncoder class)
│   └── exceptions/               # Custom exceptions (one class per file)
│       ├── not_authenticated_exception.py
│       ├── expired_token_exception.py
│       └── invalid_token_exception.py
├── tests/                        # Tests with pytest
│   ├── conftest.py              # Pytest configuration
│   ├── controllers/             # Controller tests
│   ├── services/                # Service tests
│   └── models/                  # Model tests
├── dev/                         # Development configuration
│   ├── docker-compose.yml       # Development compose
│   └── Dockerfile               # Development Dockerfile with hot-reload
├── Dockerfile                   # Production Dockerfile (multi-stage)
├── .dockerignore               # Files to ignore in Docker builds
├── pyproject.toml              # Modern project configuration (PEP 517/518)
├── template.env                # Environment variables template
└── README.md                   # Main documentation

```

### Code Organization Pattern

The project follows a **direct instantiation pattern** for services and utilities:

#### Controllers (`app/controllers/`)
Each controller creates module-level instances of services and utilities:

```python
# Example: auth_controller.py
from app.services import AuthService
from app.utils import JWTBearer, JSONEncoder, PasswordEncoder

# Module-level instances (singletons per module)
auth_service = AuthService()
jwt_bearer = JWTBearer()
json_encoder = JSONEncoder()
password_encoder = PasswordEncoder()

@router.post("/endpoint")
async def endpoint():
    # Direct usage of instances
    user = await auth_service.read_user_by_email(email)
    payload = await jwt_bearer.verify_access_token(token)
    response = json_encoder.encode(data)
    hashed = await password_encoder.hash(password)
```

**Benefits**:
- ✅ Simple and explicit
- ✅ No dependency injection complexity
- ✅ Easy to understand and maintain
- ✅ Consistent pattern across the codebase

#### Database Manager (`app/database_manager.py`)
- **DatabaseManager**: Singleton pattern for database connections
- Manages connection pools for MongoDB (Motor/Odmantic) and Neo4j
- Lifecycle management: `initialize()` on startup, `close()` on shutdown
- Provides: `get_odmantic_engine()`, `get_neo4j_driver()`

```python
# In main.py
@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager = get_database_manager()
    await db_manager.initialize()
    yield
    await db_manager.close()

# In services
class AuthService:
    def __init__(self):
        db_manager = get_database_manager()
        self._driver = db_manager.get_neo4j_driver()
        self._engine = db_manager.get_odmantic_engine()
```

**Benefits**:
- ✅ Singleton pattern ensures single connection pool
- ✅ Proper connection lifecycle management
- ✅ Configured connection pooling (min/max pool size, timeouts)
- ✅ Centralized database configuration
- ✅ Easy to mock in tests

#### Services (`app/services/`)
- **AuthService**: Business logic for authentication
- Direct instantiation: `AuthService()`
- Uses `DatabaseManager` internally for database access

#### Utilities (`app/utils/`)
All utilities are classes that are instantiated directly:

- **JWTBearer**: JWT token operations (create, verify, set cookies)
  ```python
  jwt_bearer = JWTBearer()
  token = await jwt_bearer.create_access_token(data)
  payload = await jwt_bearer.verify_access_token(token)
  ```

- **JSONEncoder**: JSON serialization with custom types (ObjectId, datetime)
  ```python
  json_encoder = JSONEncoder()
  result = json_encoder.encode(data)  # Handles ObjectId and datetime
  ```

- **PasswordEncoder**: Password hashing and verification (bcrypt)
  ```python
  password_encoder = PasswordEncoder()
  hashed = await password_encoder.hash(password)
  is_valid = await password_encoder.verify(password, hashed)
  ```

## 🔧 Technology Stack

### Core Dependencies
- **FastAPI** (0.116.1): Modern async web framework
- **Uvicorn** (0.35.0): High-performance ASGI server
- **Pydantic** (2.10.1): Data validation and settings

### Databases
- **MongoDB**: Main database (via odmantic 1.0.2)
- **Neo4j** (5.28.1): Graph database for relationships

### Authentication & Security
- **PyJWT** (2.10.1): JSON Web Token handling
- **Passlib** (1.7.4) + **bcrypt** (4.3.0): Password hashing
- **slowapi** (0.1.9): Rate limiting

### Utilities
- **APScheduler** (3.11.0): Scheduled tasks
- **aiohttp** (3.12.14): Async HTTP client
- **python-dotenv** (1.1.1): Environment variable loading
- **email-validator** (2.2.0): Email validation

### Development
- **pytest** (8.4.1) + **pytest-asyncio** (1.1.0): Testing
- **httpx** (0.28.1): HTTP client for tests
- **ruff** (0.14.0): Extremely fast linter and formatter

## 🚀 Dependency Management

The project uses **uv** (ultra-fast Python package manager) for dependency management:

### Installation with uv
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv
source .venv/bin/activate

# Install production dependencies
uv sync

# Install with development dependencies
uv sync --extra dev
```

### Alternative with pip
```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install .           # Production
pip install ".[dev]"    # With dev dependencies
```

### Configuration File
All configuration is centralized in `pyproject.toml`:
- Main dependencies: `[project.dependencies]`
- Development dependencies: `[project.optional-dependencies.dev]`
- Ruff configuration: `[tool.ruff]`

## 🐳 Docker

### Production (Multi-stage Build)
```bash
docker build -t securechain-auth:latest .
docker run -p 8000:8000 --env-file app/.env securechain-auth:latest
```

**Features**:
- Uses official uv image for fast builds
- Multi-stage: builder + slim runtime
- Optimized with .dockerignore

### Development
```bash
# Create Docker network
docker network create securechain

# Start services
docker compose -f dev/docker-compose.yml up --build
```

**Features**:
- Hot-reload enabled
- Volume mounting for live development
- Port 8001 mapped to 8000

## ⚙️ Configuration

### Environment Variables (.env)

The `.env` file should be located at `app/.env` and contain:

```bash
# Neo4j (Graph DB)
GRAPH_DB_URI=bolt://localhost:7687
GRAPH_DB_USER=neo4j
GRAPH_DB_PASSWORD=your_password

# MongoDB (Vulnerability DB)
VULN_DB_URI=mongodb://localhost:27017
VULN_DB_USER=admin
VULN_DB_PASSWORD=your_password

# JWT Configuration
JWT_ACCESS_SECRET_KEY=your_secret_key_here  # Generate with: openssl rand -base64 32
JWT_REFRESH_SECRET_KEY=your_refresh_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS
SERVICES_ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8080"]

# Security
SECURE_COOKIES=true

# Documentation (optional)
DOCS_URL=/docs  # Leave empty in production to disable
```

## 🔐 Authentication System

### Authentication Flow
1. **Signup** (`POST /auth/signup`): Create user with hashed password (bcrypt)
2. **Login** (`POST /auth/login`): Returns access_token and refresh_token (JWT)
3. **Refresh** (`POST /auth/refresh`): Renew access_token with valid refresh_token
4. **Logout** (`POST /auth/logout`): Revoke tokens
5. **Verify** (`POST /auth/verify`): Validate token

### Tokens
- **Access Token**: Short-lived (30 min default), used in every request
- **Refresh Token**: Long-lived (7 days), used only to renew access tokens
- **Revoked Tokens**: Stored in MongoDB to invalidate tokens before expiration

### Security
- Rate limiting on sensitive endpoints (login, signup)
- Passwords hashed with bcrypt (factor 12)
- Strict email and password validation
- CORS configured for allowed origins
- Secure cookies in production

## 🧪 Testing

```bash
# Install development dependencies
uv sync --extra dev

# Run all tests
pytest tests

# With verbosity
pytest tests -v

# With coverage
pytest tests --cov=app --cov-report=html
```

### Test Structure
- `tests/controllers/`: HTTP endpoint tests
- `tests/services/`: Business logic tests
- `tests/models/`: Data model tests
- `conftest.py`: Shared fixtures (HTTP client, DB mocks)

### Testing Strategy

The project uses **patch-based mocking** for testing:

```python
# Example: conftest.py - Mock DatabaseManager
_mock_db_manager_patch = patch("app.database_manager.DatabaseManager")
_mock_db_manager_class = _mock_db_manager_patch.start()
_mock_db_manager = MagicMock()
_mock_db_manager_class.return_value = _mock_db_manager

_mock_db_manager.get_odmantic_engine.return_value = AsyncMock()
_mock_db_manager.get_neo4j_driver.return_value = MagicMock()
_mock_db_manager.initialize = AsyncMock()
_mock_db_manager.close = AsyncMock()

# Example: test_auth_controller.py
@pytest.fixture(scope="session", autouse=True)
def patch_jwt():
    # Patch JWT at class level before app import
    with patch("app.utils.jwt_encoder.JWTBearer.__call__", 
               new=AsyncMock(return_value={"user_id": "abc123"})):
        yield

@pytest.fixture(autouse=True)
def mock_services():
    # Patch service instances
    with patch("app.controllers.auth_controller.auth_service") as mock_auth:
        mock_auth.read_user_by_email = AsyncMock()
        mock_auth.create_user = AsyncMock()
        # ... more async methods
        yield mock_auth
```

**Key points**:
- Mock `DatabaseManager` at **session scope** in conftest.py
- Patch `JWTBearer.__call__` at **session scope** before importing `app`
- Patch service instances at **function scope** for each test
- Use `AsyncMock` for all async methods
- Configure return values as needed per test

## 📊 Logging

The system uses structured logging:
- **File**: `errors.log` (automatic rotation)
- **Levels**: INFO, WARNING, ERROR
- **Middleware**: Logs all requests with method, path, status, and response time

## 🔄 CI/CD

### GitHub Actions

#### Python Analysis (`py-analisys.yml`)
- Trigger: push, pull_request
- Uses uv for fast installation
- Runs `ruff check app` for code analysis
- Dependency caching enabled

#### GitHub Release (`github-release.yml`)
- Trigger: tag push
- Automatic changelog generation
- Multi-architecture build (amd64, arm64)
- Push to GitHub Container Registry (ghcr.io)
- Generates SBOM and provenance for security

## 📝 Main Endpoints

### Health
- `GET /health`: Basic health check

### Auth
- `POST /auth/signup`: User registration
- `POST /auth/login`: User login
- `POST /auth/refresh`: Renew access token
- `POST /auth/logout`: Logout
- `POST /auth/verify`: Verify token
- `POST /auth/change-password`: Change password
- `GET /auth/account-exists`: Check if account exists

## 🛠️ Useful Commands

```bash
# Local development
uv sync --extra dev
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Linting and formatting
uv run ruff check app
uv run ruff format app

# Tests
pytest tests -v

# Docker
docker compose -f dev/docker-compose.yml up --build
docker compose -f dev/docker-compose.yml down

# Update dependencies
uv sync --upgrade
```

## 🎯 Project Best Practices

1. **Dependency Management**: Use `pyproject.toml` as single source of truth
2. **Typing**: Type hints in all functions
3. **Async/Await**: Use async patterns for I/O operations
4. **Validation**: Pydantic schemas for input/output validation
5. **Exceptions**: Custom exceptions with centralized handling
6. **Logging**: Structured logging with relevant context
7. **Testing**: Tests for new features before merge
8. **Security**: Never commit `.env` files, use `template.env`
9. **Code Organization**: Direct instantiation pattern for services and utilities
10. **No Comments**: Code should be self-documenting (no inline comments)

### Architecture Patterns

#### ✅ Direct Instantiation (Current Pattern)
```python
# In controllers
auth_service = AuthService()
jwt_bearer = JWTBearer()
json_encoder = JSONEncoder()

# Usage
user = await auth_service.read_user_by_email(email)
```

**Why**: Simple, explicit, easy to understand and test

#### ❌ Avoid Dependency Injection
The project intentionally avoids FastAPI's `Depends()` pattern to keep code simple and explicit.

#### ✅ Class-based Utilities
All utilities are classes that encapsulate related functionality:
- `JWTBearer`: JWT operations
- `JSONEncoder`: JSON encoding with custom types
- `PasswordEncoder`: Password hashing and verification
- `AuthService`: Authentication business logic

#### ✅ Module-level Instances
Create instances at module level (singleton per module) for reuse across endpoint handlers.

## 🔗 Important Links

- **API Documentation**: http://localhost:8001/docs (in development)
- **GitHub Org**: https://github.com/securechaindev
- **Documentation**: https://securechaindev.github.io/
- **Email**: hi@securechain.dev

## 📌 Notes for AI Agents

### When working on this project:
1. **Always verify** current content of `pyproject.toml` before adding/modifying dependencies
2. **Use uv** for package management (not pip directly)
3. **Maintain compatibility** with Python 3.13+
4. **Follow existing** directory structure
5. **Write tests** for new functionality
6. **Document** significant changes in this file and README MD
7. **Don't include** sensitive files (.env) in commits
8. **Use ruff** for linting before commit
9. **Don't write** comments in the code
10. **Write** in english

### Code Conventions:
- Line length: 88 characters (configured in ruff)
- Imports automatically sorted (isort via ruff)
- Snake_case for functions and variables
- PascalCase for classes
- Docstrings in public functions
- Type hints mandatory
- **No inline comments** - code should be self-documenting
- **Direct instantiation** - avoid dependency injection patterns
- **Class-based utilities** - group related functions in classes
- **One class per file** - following Single Responsibility Principle

### Common Patterns:

#### Creating a new utility class:
```python
# app/utils/my_utility.py
class MyUtility:
    def __init__(self):
        # Initialize if needed
        pass
    
    def method(self, param: str) -> str:
        # Implementation
        return result

# In controller
from app.utils import MyUtility

my_utility = MyUtility()
```

#### Adding a new endpoint:
```python
# In controller
@router.post("/endpoint")
@limiter.limit("25/minute")
async def endpoint(request: Request, data: Schema) -> JSONResponse:
    result = await auth_service.method(data)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode({"detail": result})
    )
```

#### Testing pattern:
```python
def test_endpoint(mock_services):
    mock_auth = mock_services
    mock_auth.method.return_value = expected_value
    
    response = client.post("/endpoint", json={"data": "value"})
    assert response.status_code == 200
```

### Debugging:
- Logs in `errors.log`
- FastAPI docs at `/docs` (development only)
- Use `pytest -v -s` to see prints in tests

---

**Last updated**: October 15, 2025  
**Maintained by**: Secure Chain Team
