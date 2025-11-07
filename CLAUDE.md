# SecureChain Auth - Project Context

> **Context file for AI agents**: This document provides a complete overview of the project to facilitate work in new sessions.

## 📋 General Information

- **Project Name**: securechain-auth
- **Version**: 1.1.1
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
│   │   ├── user_controller.py    # User authentication and registration
│   │   ├── api_key_controller.py # API Key management
│   │   └── health_controller.py  # Health checks
│   ├── services/                 # Business logic
│   │   ├── user_service.py       # User authentication service
│   │   └── api_key_service.py    # API Key service
│   ├── database_manager.py       # Database connection manager (Singleton)
│   ├── constants.py              # Application constants and configurations
│   ├── models/                   # Data models (ODM/OGM)
│   │   └── auth/
│   │       ├── User.py           # User model
│   │       ├── ApiKey.py         # API Key model
│   │       └── RevokedToken.py   # Revoked tokens
│   ├── schemas/                  # Pydantic schemas for validation
│   │   ├── auth/                 # Authentication schemas
│   │   ├── patterns/             # Regex patterns for validation
│   │   └── validators/           # Custom validators
│   ├── utils/                    # Utilities
│   │   ├── jwt_bearer.py         # JWT encoding/decoding (JWTBearer class)
│   │   ├── apikey_bearer.py      # API Key operations (ApiKeyBearer class)
│   │   ├── password_encoder.py   # Password hashing (PasswordEncoder class)
│   │   └── json_encoder.py       # Custom JSON encoder (JSONEncoder class)
│   └── exceptions/               # Custom exceptions (one class per file)
│       ├── not_authenticated_exception.py
│       ├── expired_token_exception.py
│       ├── invalid_token_exception.py
│       └── api_key_name_exists_exception.py
├── tests/                        # Tests with pytest
│   ├── conftest.py              # Pytest configuration and fixtures
│   ├── unit/                    # 79 unit tests
│   │   ├── controllers/         # Controller tests
│   │   ├── services/            # Service tests (UserService + ApiKeyService)
│   │   ├── models/              # Model tests
│   │   ├── utils/               # Utility tests
│   │   └── exceptions/          # Exception handler tests
│   ├── integration/             # 3 integration tests
│   │   └── test_api_integration.py
│   └── README.md                # Testing documentation
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

The project follows a **layered dependency pattern** with different instantiation strategies based on resource requirements:

#### Pattern Decision Matrix

| Component Type | Pattern | Reason | Example |
|---------------|---------|--------|---------|
| **Database Connections** | Singleton (`__new__`) | Manages expensive resources (connection pools) | `DatabaseManager` |
| **Stateful Services** | Dependency Injection (`Depends()`) | Per-request lifecycle, needs mocking | `UserService`, `ApiKeyService` |
| **Stateless Utilities** | Module-level instance | No state, no resources, pure functions | `jwt_bearer`, `password_encoder`, `apikey_bearer` |

#### Controllers (`app/controllers/`)
Controllers use FastAPI's dependency injection (`Depends()`) for services, but direct instantiation for utilities:

```python
# Example: user_controller.py
from fastapi import Depends
from app.services import UserService
from app.utils import JWTBearer, JSONEncoder, PasswordEncoder
from app.database import DatabaseManager, get_database_manager

# Module-level utility instances (stateless, no resources)
jwt_bearer = JWTBearer()
json_encoder = JSONEncoder()
password_encoder = PasswordEncoder()

# Dependency injection for services (stateful, needs lifecycle)
def get_user_service(db: DatabaseManager = Depends(get_database_manager)) -> UserService:
    return UserService(db)

@router.post("/endpoint")
async def endpoint(
    user_service: UserService = Depends(get_user_service)
):
    # Injected service (per-request)
    user = await user_service.read_user_by_email(email)
    # Direct utility usage (shared instance)
    payload = jwt_bearer.verify_access_token(token)
    response = json_encoder.encode(data)
    hashed = password_encoder.hash(password)
```

**Benefits**:
- ✅ Proper lifecycle management for database connections
- ✅ Easy to test with `app.dependency_overrides`
- ✅ Clear separation: Singleton for resources, DI for services, direct for utilities
- ✅ Follows FastAPI best practices
- ✅ No unnecessary complexity for stateless components

#### Database Manager (`app/database.py`)

**Singleton Pattern** (`__new__` override) for resource management:

```python
class DatabaseManager:
    _instance: "DatabaseManager | None" = None
    _mongo_client: AsyncIOMotorClient | None = None
    _neo4j_driver: AsyncDriver | None = None
    _odmantic_engine: AIOEngine | None = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        # Create connection pools for MongoDB and Neo4j
        pass

    async def close(self) -> None:
        # Close all connections
        pass

    def get_odmantic_engine(self) -> AIOEngine:
        if self._odmantic_engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._odmantic_engine

    def get_neo4j_driver(self) -> AsyncDriver:
        if self._neo4j_driver is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._neo4j_driver
```

**Factory function** for dependency injection:
```python
_db_manager: DatabaseManager | None = None

def get_database_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
```

**Lifecycle management** in `main.py`:
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager = get_database_manager()
    await db_manager.initialize()
    yield
    await db_manager.close()

app = FastAPI(lifespan=lifespan)
```

**Why Singleton here?**
- ✅ Ensures **single connection pool** for MongoDB and Neo4j
- ✅ Prevents resource exhaustion from multiple connection pools
- ✅ Proper connection lifecycle management (startup/shutdown)
- ✅ Configured connection pooling (min/max pool size, timeouts)
- ✅ Centralized database configuration
- ✅ Easy to mock in tests with `app.dependency_overrides`

**When NOT to use Singleton:**
- ❌ Stateless utilities (use module-level instances instead)
- ❌ Components without expensive resources
- ❌ When you need multiple instances with different configurations

#### Services (`app/services/`)
- **UserService**: Business logic for user authentication and management
- **ApiKeyService**: Business logic for API key management
- **Dependency injection**: Receives `DatabaseManager` as constructor parameter
- Uses `DatabaseManager` for database access

```python
class UserService:
    def __init__(self, db: DatabaseManager):
        self._db = db
        self._engine = db.get_odmantic_engine()
        self._driver = db.get_neo4j_driver()

class ApiKeyService:
    def __init__(self, db: DatabaseManager):
        self._db = db
        self._engine = db.get_odmantic_engine()
```

**Factory functions** for dependency injection:
```python
def get_user_service(db: DatabaseManager = Depends(get_database_manager)) -> UserService:
    return UserService(db)

def get_api_key_service(db: DatabaseManager = Depends(get_database_manager)) -> ApiKeyService:
    return ApiKeyService(db)
```

#### Utilities (`app/utils/`)
All utilities are classes that are instantiated directly at module level as **stateless singletons**. These are **synchronous methods** (not async) as they don't perform I/O operations:

- **JWTBearer**: JWT token operations (create, verify, set cookies)
  ```python
  jwt_bearer = JWTBearer()
  token = jwt_bearer.create_access_token(data)
  payload = jwt_bearer.verify_access_token(token)
  jwt_bearer.set_auth_cookies(response, access_token, refresh_token)
  ```

- **ApiKeyBearer**: API Key operations (generate, hash, verify)
  ```python
  apikey_bearer = ApiKeyBearer()
  api_key = apikey_bearer.generate()
  hashed = apikey_bearer.hash(api_key)
  is_valid = apikey_bearer.verify(api_key, hashed)
  ```

- **JSONEncoder**: JSON serialization with custom types (ObjectId, datetime)
  ```python
  json_encoder = JSONEncoder()
  result = json_encoder.encode(data)  # Handles ObjectId and datetime
  ```

- **PasswordEncoder**: Password hashing and verification (bcrypt)
  ```python
  password_encoder = PasswordEncoder()
  hashed = password_encoder.hash(password)
  is_valid = password_encoder.verify(password, hashed)
  ```

**Why module-level instances (not Singleton pattern)?**
- ✅ Stateless components (no expensive resources to manage)
- ✅ More pythonic than explicit Singleton
- ✅ Same result: single instance per module
- ✅ Simpler code, no `__new__` override needed
- ✅ Easy to patch in tests with `unittest.mock.patch`

**Note**: These utilities use synchronous methods (not async/await) because they perform CPU-bound operations (hashing, encoding) rather than I/O-bound operations.

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
- **pytest** (8.4.2) + **pytest-asyncio** (1.2.0): Testing
- **pytest-cov** (7.0.0): Test coverage
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

The project has a comprehensive test suite with **86% coverage** organized into unit and integration tests.

### Test Structure

```
tests/
├── unit/                    # 79 unit tests
│   ├── controllers/        # Endpoint tests with mocked dependencies
│   ├── models/             # Data model validation tests
│   ├── services/           # Business logic tests (UserService + ApiKeyService)
│   ├── utils/              # Utility function tests
│   └── exceptions/         # Exception handler tests
├── integration/            # 3 integration tests
│   └── test_api_integration.py
├── conftest.py             # Shared fixtures and configuration
└── README.md               # Testing documentation
```

### Running Tests

```bash
# Install test dependencies
uv sync --extra test

# Run all tests (82 total)
pytest tests/

# Run only unit tests (79 tests)
pytest tests/unit/
pytest -m unit

# Run only integration tests (3 tests)
pytest tests/integration/
pytest -m integration

# With coverage report
pytest tests/ --cov=app --cov-report=term-missing

# Generate HTML coverage report
pytest tests/ --cov=app --cov-report=html
# View at: htmlcov/index.html

# With verbosity
pytest tests/ -v
```

### Coverage Report

Current coverage: **84%**

High coverage modules (90%+):
- Controllers: 99%
- Models: 100%
- Services: 100% (UserService + ApiKeyService)
- Schemas & Validators: 100%
- Utils: 86-100%

Lower coverage (by design):
- Database connection code: 37% (requires real DB for testing)
- Main app initialization: 86%
- Middleware: 90%

### Testing Strategy

The project uses **dependency injection mocking** with `app.dependency_overrides` for testing. Tests are automatically marked based on their location (unit/integration).

#### Test Configuration (conftest.py)

```python
def pytest_collection_modifyitems(items):
    """Automatically mark tests based on their location."""
    for item in items:
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

@pytest.fixture(scope="session")
def mock_db_manager():
    """Create a mock DatabaseManager for all tests."""
    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = AsyncMock()
    mock_db.get_neo4j_driver.return_value = MagicMock()
    mock_db.initialize = AsyncMock()
    mock_db.close = AsyncMock()
    return mock_db

@pytest.fixture(scope="session")
def mock_user_service():
    """Create a mock UserService for controller tests."""
    mock_user = MagicMock()
    mock_user.read_user_by_email = AsyncMock()
    mock_user.create_user = AsyncMock()
    mock_user.create_revoked_token = AsyncMock()
    mock_user.update_user_password = AsyncMock()
    mock_user.is_token_revoked = AsyncMock()
    return mock_user

@pytest.fixture(scope="function")
def client(mock_db_manager, mock_user_service):
    """Create a TestClient with dependency overrides for each test."""
    from app.main import app
    from app.controllers.user_controller import get_user_service
    from app.database import get_database_manager
    
    # Disable lifespan for tests
    @asynccontextmanager
    async def test_lifespan(app):
        yield
    
    app.router.lifespan_context = test_lifespan
    
    # Override dependencies
    app.dependency_overrides[get_database_manager] = lambda: mock_db_manager
    app.dependency_overrides[get_user_service] = lambda: mock_user_service
    
    with TestClient(app) as c:
        yield c
    
    app.dependency_overrides.clear()
```

#### Unit Test Example

```python
# tests/unit/controllers/test_user_controller.py
def test_login_success(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = User(email="test@example.com", password="hashed")

    with patch("app.controllers.user_controller.password_encoder.verify", return_value=True), \
         patch("app.controllers.user_controller.jwt_bearer.create_access_token", return_value="access"), \
         patch("app.controllers.user_controller.jwt_bearer.create_refresh_token", return_value="refresh"):
        response = client.post("/user/login", json={"email": "test@example.com", "password": "13pAssword*"})
        assert response.status_code == 200
        assert response.json()["code"] == "login_success"
```

#### Integration Test Example

```python
# tests/integration/test_api_integration.py
def test_health_endpoint_integration(client):
    """Test that the health endpoint returns OK status."""
    response = client.get("/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["detail"] == "healthy"
```

#### Service Test Example

```python
# tests/unit/services/test_user_service.py
@pytest.mark.asyncio
async def test_create_user_saves_user_and_creates_graph():
    mock_engine = AsyncMock()
    mock_driver = MagicMock()
    mock_session = AsyncMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    
    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = mock_engine
    mock_db.get_neo4j_driver.return_value = mock_driver
    
    # Inject mock DatabaseManager to service
    service = UserService(mock_db)
    
    await service.create_user({"email": "test@example.com", "password": "pass"})
    
    mock_engine.save.assert_called_once()
    mock_session.run.assert_called_once()
```

**Key points**:
- Use `app.dependency_overrides` to mock dependencies
- Mock `DatabaseManager`, `UserService`, `ApiKeyService`, and `jwt_bearer` at session scope
- Create fresh `TestClient` per test function with overrides
- Disable lifespan context manager for tests
- For service tests, inject mock `DatabaseManager` to constructor
- Use `AsyncMock` for all async methods
- Clear overrides after each test

**Testing Checklist**:
- ✅ Controller tests use `app.dependency_overrides`
- ✅ Service tests inject mock `DatabaseManager`
- ✅ All async methods use `AsyncMock()`
- ✅ Protected routes mock `jwt_bearer` dependency
- ✅ Database connections never initialized in tests
- ✅ All 82 tests passing without warnings

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
- `POST /user/signup`: User registration
- `POST /user/login`: User login
- `POST /user/refresh_token`: Renew access token
- `POST /user/logout`: Logout
- `POST /user/check_token`: Verify token
- `POST /user/change_password`: Change password
- `POST /user/account_exists`: Check if account exists

### API Keys
- `POST /apikey/create`: Create new API key
- `GET /apikey/list`: List user's API keys
- `POST /apikey/revoke`: Revoke an API key

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
9. **Code Organization**: 
   - Dependency injection for services (use `Depends()`)
   - Direct instantiation for utilities (module-level instances)
   - DatabaseManager singleton with proper lifecycle
10. **No Comments**: Code should be self-documenting (no inline comments)

### Architecture Patterns

This section explains **when and why** to use each pattern in the project.

#### Pattern Decision Guide

**Use Singleton (`__new__` override) when:**
- ✅ Managing **expensive resources** (database connections, connection pools)
- ✅ Need **lifecycle management** (initialize/close)
- ✅ Want to **prevent multiple instances** that would waste resources
- ✅ Example: `DatabaseManager` (manages MongoDB and Neo4j connection pools)

**Use Dependency Injection (`Depends()`) when:**
- ✅ Component has **per-request lifecycle** (created/destroyed each request)
- ✅ Needs to be **easily mocked** in tests
- ✅ Has **dependencies** that need to be injected
- ✅ Example: `UserService`, `ApiKeyService` (depends on `DatabaseManager`, mocked in tests)

**Use Module-level instance when:**
- ✅ Component is **stateless** (no internal state to manage)
- ✅ Doesn't manage **expensive resources**
- ✅ Contains only **pure functions** or CPU-bound operations
- ✅ Example: `jwt_bearer`, `password_encoder`, `json_encoder`, `apikey_bearer` (just utilities)

#### ✅ Dependency Injection for Services (Current Pattern)
```python
# In controllers - use FastAPI Depends()
from fastapi import Depends

def get_user_service(db: DatabaseManager = Depends(get_database_manager)) -> UserService:
    return UserService(db)

@router.post("/endpoint")
async def endpoint(
    user_service: UserService = Depends(get_user_service)
):
    user = await user_service.read_user_by_email(email)
```

**Why**: Proper lifecycle management, easy testing with `app.dependency_overrides`

#### ✅ Direct Instantiation for Utilities
```python
# In controllers - module-level instances
jwt_bearer = JWTBearer()
json_encoder = JSONEncoder()
password_encoder = PasswordEncoder()
apikey_bearer = ApiKeyBearer()

# Usage
token = jwt_bearer.create_access_token(user_id)
response = json_encoder.encode(data)
hashed = password_encoder.hash(password)
api_key = apikey_bearer.generate()
```

**Why**: Stateless utilities don't need lifecycle management or injection

#### ✅ Class-based Utilities
All utilities are classes that encapsulate related functionality:
- `JWTBearer`: JWT operations
- `ApiKeyBearer`: API Key operations
- `JSONEncoder`: JSON encoding with custom types
- `PasswordEncoder`: Password hashing and verification

#### ✅ DatabaseManager Singleton
```python
class DatabaseManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    async def initialize(self):
        # Create connection pools
        pass
    
    async def close(self):
        # Close connections
        pass

def get_database_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
```

**Why**: Single connection pool, proper resource management, prevents resource exhaustion

#### ✅ Dependency Hierarchy
```
DatabaseManager (singleton with __new__)
    ↓ (injected via Depends)
UserService / ApiKeyService (per request via Depends)
    ↓ (injected via Depends)
Endpoints (request handlers)
```

Utilities (`jwt_bearer`, `apikey_bearer`, `json_encoder`, `password_encoder`) are used directly without injection.

#### ❌ Anti-patterns to Avoid

**DON'T create a unified dependencies.py file** with all singletons unless:
- You have 5+ services managing resources
- Complex initialization dependencies between services
- Need conditional service selection (prod vs dev implementations)

**Current project size**: 1 resource manager (DatabaseManager) + 3 stateless utilities  
**Conclusion**: Current pattern is optimal, no need for additional abstraction

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
- **Dependency injection for services** - use FastAPI `Depends()` pattern
- **Direct instantiation for utilities** - module-level instances
- **DatabaseManager singleton** - with proper lifecycle management
- **One class per file** - following Single Responsibility Principle

### Common Patterns:

#### Creating a new service with dependency injection:
```python
# app/services/my_service.py
from app.database import DatabaseManager

class MyService:
    def __init__(self, db: DatabaseManager):
        self._db = db
        self._engine = db.get_odmantic_engine()
        self._driver = db.get_neo4j_driver()
    
    async def method(self, param: str) -> str:
        # Implementation using self._engine or self._driver
        return result

# In controller
from fastapi import Depends
from app.database import get_database_manager
from app.services import MyService

def get_my_service(db: DatabaseManager = Depends(get_database_manager)) -> MyService:
    return MyService(db)

@router.post("/endpoint")
async def endpoint(
    my_service: MyService = Depends(get_my_service)
):
    result = await my_service.method(param)
```

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

my_utility = MyUtility()  # Module-level instance

@router.post("/endpoint")
async def endpoint():
    result = my_utility.method(param)
```

#### Adding a new endpoint:
```python
# In controller
@router.post("/endpoint")
@limiter.limit("25/minute")
async def endpoint(
    request: Request,
    data: Schema,
    auth_service: AuthService = Depends(get_auth_service)
) -> JSONResponse:
    result = await auth_service.method(data)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode({"detail": result})
    )
```

#### Testing pattern with dependency injection:
```python
# In test file
def test_endpoint(client, mock_user_service):
    mock_user_service.method.return_value = expected_value
    
    response = client.post("/endpoint", json={"data": "value"})
    assert response.status_code == 200
    assert response.json()["code"] == expected_value

# For service tests
@pytest.mark.asyncio
async def test_service_method():
    mock_db = MagicMock()
    mock_db.get_odmantic_engine.return_value = AsyncMock()
    
    service = MyService(mock_db)
    result = await service.method("param")
    
    assert result == expected
```

### Debugging:
- Logs in `errors.log`
- FastAPI docs at `/docs` (development only)
- Use `pytest -v -s` to see prints in tests

---

**Last updated**: November 5, 2025  
**Maintained by**: Secure Chain Team
