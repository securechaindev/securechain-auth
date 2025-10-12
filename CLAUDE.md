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
│   │   ├── auth_service.py       # Authentication service
│   │   └── dbs/                  # Database services
│   ├── models/                   # Data models (ODM/OGM)
│   │   └── auth/
│   │       ├── User.py           # User model
│   │       └── RevokedToken.py   # Revoked tokens
│   ├── schemas/                  # Pydantic schemas for validation
│   │   ├── auth/                 # Authentication schemas
│   │   ├── patterns/             # Regex patterns for validation
│   │   └── validators/           # Custom validators
│   ├── utils/                    # Utilities
│   │   ├── jwt_encoder.py        # JWT encoding/decoding
│   │   ├── password_encoder.py   # Password hashing (bcrypt)
│   │   └── json_encoder.py       # Custom JSON encoders
│   └── exceptions/               # Custom exceptions
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

### Debugging:
- Logs in `errors.log`
- FastAPI docs at `/docs` (development only)
- Use `pytest -v -s` to see prints in tests

---

**Last updated**: October 12, 2025  
**Maintained by**: Secure Chain Team
