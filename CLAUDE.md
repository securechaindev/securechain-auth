# SecureChain Auth - Project Context

> **Context file for AI agents**: This document provides essential project context. **Maximum 500 lines** - keep only critical information.

## 📋 General Information

- **Project**: securechain-auth
- **Version**: 1.1.3
- **Framework**: FastAPI 0.116.1
- **Python**: 3.14+
- **Database**: MongoDB (pymongo) + Neo4j
- **Repository**: https://github.com/securechaindev/login_backend

## 🏗️ Architecture

### Directory Structure
```
app/
├── main.py                   # FastAPI entry point
├── settings.py               # Config with pydantic-settings
├── router.py                 # Main router
├── database.py               # DatabaseManager singleton
├── controllers/              # Endpoints
│   ├── user_controller.py    # Auth endpoints
│   ├── api_key_controller.py # API key endpoints
│   └── health_controller.py  # Health check
├── services/                 # Business logic (dict-based, no ORM)
│   ├── user_service.py       # Returns/accepts dicts
│   └── api_key_service.py    # Returns/accepts dicts
├── schemas/                  # Pydantic validation
│   ├── auth/                 # Request/response schemas
│   ├── patterns/             # Regex validators
│   └── validators/           # Custom validators
├── utils/                    # Stateless utilities
│   ├── jwt_bearer.py         # JWT operations
│   ├── apikey_bearer.py      # API key operations
│   ├── password_encoder.py   # bcrypt hashing
│   └── json_encoder.py       # JSON with ObjectId/datetime
├── exceptions/               # Custom exceptions
└── constants.py              # App constants
tests/
├── unit/                     # 52 unit tests
│   ├── controllers/          # Controller tests
│   ├── services/             # Service tests (14 tests)
│   ├── utils/                # Utility tests
│   └── exceptions/           # Exception tests
└── integration/              # 3 integration tests
```

### Architecture Pattern

**IMPORTANT: No ORM - Direct MongoDB dict operations**
- **Removed**: odmantic (incompatible with Python 3.14)
- **Current**: Work directly with dicts using pymongo AsyncMongoClient
- **Models**: Deleted `app/models/` directory - validation only in Pydantic schemas
- **Services**: Return/accept plain dicts with MongoDB structure (`{"_id": ObjectId(), ...}`)

| Component | Pattern | Why |
|-----------|---------|-----|
| Database | Singleton | Single connection pool |
| Services | DI (`Depends()`) | Per-request, easy mocking |
| Utilities | Module-level | Stateless, no resources |

### Code Patterns

#### Controllers
```python
# Utilities: direct instantiation (module-level)
jwt_bearer = JWTBearer()
json_encoder = JSONEncoder()
password_encoder = PasswordEncoder()

# Services: dependency injection
def get_user_service(db: DatabaseManager = Depends(get_database_manager)) -> UserService:
    return UserService(db)

@router.post("/endpoint")
async def endpoint(user_service: UserService = Depends(get_user_service)):
    user = await user_service.read_user_by_email(email)  # Returns dict
    token = jwt_bearer.create_access_token({"user_id": str(user["_id"])})
    return json_encoder.encode({"token": token})
```

#### Services (dict-based)
```python
class UserService:
    def __init__(self, db: DatabaseManager):
        self.driver = db.get_neo4j_driver()
        self.users_collection = db.get_users_collection()  # AsyncCollection
        self.revoked_tokens_collection = db.get_revoked_tokens_collection()

    async def read_user_by_email(self, email: str) -> dict | None:
        return await self.users_collection.find_one({"email": email})  # Returns dict

    async def create_user(self, email: str, password: str) -> None:
        result = await self.users_collection.insert_one({"email": email, "password": password})
        user_id = str(result.inserted_id)
        # Create node in Neo4j
        async with self.driver.session() as session:
            await session.run("CREATE (u:User {_id: $user_id})", user_id=user_id)
```

#### Database Manager (Singleton)
```python
class DatabaseManager:
    _instance: "DatabaseManager | None" = None
    _mongo_client: AsyncMongoClient | None = None
    _neo4j_driver: AsyncDriver | None = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_users_collection(self):
        return self.get_mongo_db()["users"]

    def get_api_keys_collection(self):
        return self.get_mongo_db()["api_keys"]

    def get_revoked_tokens_collection(self):
        return self.get_mongo_db()["revoked_tokens"]
```

## 🔧 Dependencies

### Core
- FastAPI 0.116.1, Uvicorn 0.35.0, Pydantic 2.10.1
- MongoDB: pymongo 4.15.4 (async driver)
- Neo4j 5.28.1 (graph database)
- PyJWT 2.10.1, bcrypt 5.0.0 (direct usage, no passlib)
- slowapi 0.1.9 (rate limiting)

### Development
- pytest 8.4.2 + pytest-asyncio 1.3.0 + pytest-cov 7.0.0
- ruff 0.14.0 (linting/formatting)

**IMPORTANT**: odmantic removed (incompatible with Python 3.14)

## 🚀 Setup

```bash
# Install uv (fast package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create environment and install dependencies
uv venv
source .venv/bin/activate
uv sync --extra dev

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Run tests (58 tests, 83% coverage)
pytest -v

# Linting
uv run ruff check app
uv run ruff format app
```

## ⚙️ Configuration

Create `app/.env`:
```bash
# MongoDB
VULN_DB_URI=mongodb://localhost:27017
VULN_DB_USER=admin
VULN_DB_PASSWORD=password

# Neo4j
GRAPH_DB_URI=bolt://localhost:7687
GRAPH_DB_USER=neo4j
GRAPH_DB_PASSWORD=password

# JWT
JWT_ACCESS_SECRET_KEY=<openssl rand -base64 32>
JWT_REFRESH_SECRET_KEY=<openssl rand -base64 32>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS
SERVICES_ALLOWED_ORIGINS=["http://localhost:3000"]

# Security
SECURE_COOKIES=true
```

## 🔐 Authentication

### Flow
1. **Signup** (`POST /user/signup`): Hash password with bcrypt, store user dict in MongoDB
2. **Login** (`POST /user/login`): Verify password, return JWT access + refresh tokens
3. **Refresh** (`POST /user/refresh_token`): Renew access token with valid refresh token
4. **Logout** (`POST /user/logout`): Add token to revoked_tokens collection
5. **Verify** (`POST /user/check_token`): Validate token

### Tokens
- **Access**: 30 min, used in all requests
- **Refresh**: 7 days, only for token renewal
- **Revoked**: Stored in MongoDB until expiration

### Security
- Rate limiting on auth endpoints
- bcrypt factor 12
- Email/password validation with Pydantic
- CORS configuration
- Secure cookies in production

## 🧪 Testing

**58 tests, 83% coverage**

```bash
# Run all tests
pytest -v

# Unit tests only (52 tests)
pytest tests/unit/ -v

# Integration tests only (3 tests)
pytest tests/integration/ -v

# With coverage
pytest --cov=app --cov-report=html
```

### Test Strategy

**Use `app.dependency_overrides` for mocking:**
```python
# conftest.py
@pytest.fixture
def mock_db_manager():
    mock = MagicMock()
    mock.get_users_collection.return_value = AsyncMock()
    mock.get_api_keys_collection.return_value = AsyncMock()
    mock.get_revoked_tokens_collection.return_value = AsyncMock()
    mock.get_neo4j_driver.return_value = MagicMock()
    return mock

@pytest.fixture
def client(mock_db_manager):
    app.dependency_overrides[get_database_manager] = lambda: mock_db_manager
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

# Test example
def test_login(client, mock_user_service):
    mock_user_service.read_user_by_email.return_value = {
        "_id": ObjectId(),
        "email": "test@example.com",
        "password": "hashed"
    }
    response = client.post("/user/login", json={"email": "test@example.com", "password": "Pass1*"})
    assert response.status_code == 200
```

### Service Tests (dict-based)
```python
@pytest.mark.asyncio
async def test_create_user():
    mock_users_collection = AsyncMock()
    mock_users_collection.insert_one = AsyncMock(return_value=MagicMock(inserted_id=ObjectId()))
    
    mock_db = MagicMock()
    mock_db.get_users_collection.return_value = mock_users_collection
    mock_db.get_neo4j_driver.return_value = MagicMock()
    
    service = UserService(mock_db)
    await service.create_user("test@example.com", "hashed_pass")
    
    mock_users_collection.insert_one.assert_called_once()
```

**Key Points:**
- Mock collections return dicts with `ObjectId()` for `_id`
- Use `AsyncMock()` for all async methods
- Services receive mock `DatabaseManager` in constructor
- Controllers use `app.dependency_overrides`

## 📝 Main Endpoints

### Auth
- `POST /user/signup` - Register user
- `POST /user/login` - Login
- `POST /user/refresh_token` - Renew access token
- `POST /user/logout` - Logout
- `POST /user/check_token` - Verify token
- `POST /user/change_password` - Change password
- `POST /user/account_exists` - Check if account exists

### API Keys
- `POST /apikey/create` - Create API key
- `GET /apikey/list` - List user's API keys
- `POST /apikey/revoke` - Revoke API key

### Health
- `GET /health` - Health check

## 🎯 Best Practices & Conventions

### Code Style
- **Python 3.14+** compatibility
- **Type hints** mandatory
- **No comments** - self-documenting code
- **Line length**: 88 chars (ruff)
- **Naming**: snake_case (functions/vars), PascalCase (classes)
- **One class per file**
- **Async/await** for I/O operations

### Architecture Decisions

**Use Singleton (`__new__`) when:**
- Managing expensive resources (connection pools)
- Need lifecycle management (initialize/close)
- Example: `DatabaseManager`

**Use Dependency Injection (`Depends()`) when:**
- Per-request lifecycle
- Needs mocking in tests
- Has dependencies to inject
- Example: `UserService`, `ApiKeyService`

**Use Module-level instance when:**
- Stateless utilities
- No expensive resources
- Pure functions or CPU-bound operations
- Example: `jwt_bearer`, `password_encoder`, `json_encoder`

### Common Patterns

#### New Service with DI
```python
# app/services/my_service.py
class MyService:
    def __init__(self, db: DatabaseManager):
        self.collection = db.get_mongo_db()["my_collection"]
    
    async def get_item(self, item_id: str) -> dict | None:
        return await self.collection.find_one({"_id": ObjectId(item_id)})

# In controller
def get_my_service(db: DatabaseManager = Depends(get_database_manager)) -> MyService:
    return MyService(db)

@router.get("/item/{item_id}")
async def get_item(
    item_id: str,
    service: MyService = Depends(get_my_service)
):
    item = await service.get_item(item_id)
    return json_encoder.encode(item)
```

#### New Utility Class
```python
# app/utils/my_utility.py
class MyUtility:
    def process(self, data: str) -> str:
        return data.upper()

# In controller (module-level)
my_utility = MyUtility()

@router.post("/process")
async def process(data: str):
    result = my_utility.process(data)
    return {"result": result}
```

#### Testing with Mocks
```python
# Controller test
def test_endpoint(client, mock_service):
    mock_service.method.return_value = {"_id": ObjectId(), "data": "value"}
    response = client.post("/endpoint", json={"input": "test"})
    assert response.status_code == 200

# Service test
@pytest.mark.asyncio
async def test_service():
    mock_collection = AsyncMock()
    mock_collection.find_one.return_value = {"_id": ObjectId(), "email": "test@test.com"}
    
    mock_db = MagicMock()
    mock_db.get_mongo_db.return_value.__getitem__.return_value = mock_collection
    
    service = MyService(mock_db)
    result = await service.get_item("123")
    assert result["email"] == "test@test.com"
```

### Important Notes
- **No ORM**: Work directly with dicts and pymongo
- **Dict structure**: Use `{"_id": ObjectId(), ...}` format
- **Services return dicts**: Not model objects
- **Validation in schemas**: Pydantic handles validation
- **bcrypt direct**: No passlib wrapper
- **Python 3.14 only**: odmantic incompatible, removed

---

**Last updated**: November 22, 2025  
**Version**: 1.1.3  
**Maintained by**: Secure Chain Team
