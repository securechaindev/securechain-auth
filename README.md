# Secure Chain Auth

[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Lint & Test](https://github.com/securechaindev/securechain-auth/actions/workflows/lint-test.yml/badge.svg)]()
[![GHCR](https://img.shields.io/badge/GHCR-securechain--auth-blue?logo=docker)](https://github.com/orgs/securechaindev/packages/container/package/securechain-auth)

An authentication service for Secure Chain tools, built with FastAPI. This service provides:
- **User authentication**: Registration, login, password management with JWT tokens
- **API Key management**: Service-to-service authentication for microservices
- **Dual authentication**: Support for both JWT (users) and API Keys (services)
- **Database support**: MongoDB for data storage and Neo4j for graph relationships

## Features

### User Authentication
- 🔐 JWT-based authentication with access and refresh tokens
- 👤 User registration and login
- 🔑 Password change functionality
- 🚪 Logout with token revocation
- ✅ Token validation and account existence checks

### API Key Management
- 🔑 Create API Keys for service-to-service authentication
- 📋 List all API Keys for a user
- ❌ Revoke API Keys
- ⏱️ Optional expiration dates
- 🔒 Secure key hashing with SHA-256

## Development requirements

1. [Docker](https://www.docker.com/) to deploy the tool.
2. [Docker Compose](https://docs.docker.com/compose/) for container orchestration.
3. It is recommended to use a GUI such as [MongoDB Compass](https://www.mongodb.com/en/products/compass).
4. Python 3.14 or higher.
5. [uv](https://github.com/astral-sh/uv) - Ultra-fast Python package manager (optional but recommended).

## Setup development profile

### 1. Clone the repository
```bash
git clone https://github.com/securechaindev/securechain-auth.git
cd securechain-auth
```

### 2. Configure environment variables
Create a `.env` file from the `.env.template` file and place it in the `app/` directory. Modify the **Json Web Token (JWT)** secret key and algorithm with your own. You can generate your own secret key with the command **openssl rand -base64 32**.

### 3. Create Docker network
Ensure you have the `securechain` Docker network created. If not, create it with:
```bash
docker network create securechain
```

### 4. Start the application
Run the command from the project root:
```bash
docker compose -f dev/docker-compose.yml up --build
```

### 5. Access the application
The API will be available at [http://localhost:8001](http://localhost:8002). You can access the API documentation at [http://localhost:8001/docs](http://localhost:8002/docs).

## API Key Authentication (for services)
Used by microservices for service-to-service communication:

```bash
# Create an API Key (requires JWT authentication)
# Then use API Key in other microservices
curl "https://securechain.dev/api/some_endpoint" -H "X-API-Key: sk_your_api_key_here"
```

## Development Environment

The project uses Python 3.14 and [uv](https://github.com/astral-sh/uv) as the package manager for faster and more reliable dependency management.

### Setting up the development environment using uv

1. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Create and activate a virtual environment**:
   ```bash
   uv venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   uv sync
   ```

## Testing

```bash
# Install test dependencies
uv sync --extra test

# Run all tests
uv run pytest

# Run tests with coverage report
uv run pytest --cov=app --cov-report=term-missing --cov-report=html

# Run specific test file
uv run pytest tests/unit/controllers/test_graph_controller.py -v

# Run only unit tests
uv run pytest tests/unit/ -v
```

## Code Quality

```bash
# Install linter
uv sync --extra dev

# Linting
uv run ruff check app/

# Formatting
uv run ruff format app/
```

## Contributing

Pull requests are welcome! To contribute follow this [guidelines](https://securechaindev.github.io/contributing.html).

## License
[GNU General Public License 3.0](https://www.gnu.org/licenses/gpl-3.0.html)

## Links
- [Secure Chain Team](mailto:hi@securechain.dev)
- [Secure Chain Organization](https://github.com/securechaindev)
- [Secure Chain Documentation](https://securechaindev.github.io/)
