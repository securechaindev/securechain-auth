# Secure Chain User Backend

A simple user registry backend for Secure Chain tools, built with FastAPI. This service provides user authentication, registration, password management, and token-based security, with support for MongoDB and Neo4j databases.

## Requirements
- Python 3.10+
- MongoDB & MongoDB Compass
- Neo4j
- Docker

## Setup development profile

### 1. Clone the repository
```bash
git clone https://github.com/securechaindev/login_backend.git
cd login_backend
```

### 2. Install dependencies
```bash
python -m venv securechain-login-env
source securechain-login-env/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables
Copy the template and fill in your secrets:
```bash
cp template.env app/.env
```
Edit `.env` with your database URIs, credentials, and JWT secrets. Example:
```
GRAPH_DB_URI='bolt://localhost:7687'
VULN_DB_URI='mongodb://mongoSecureChain:mongoSecureChain@localhost:27017/admin'
GRAPH_DB_USER='neo4j'
GRAPH_DB_PASSWORD='neoSecureChain'
VULN_DB_USER='mongoSecureChain'
VULN_DB_PASSWORD='mongoSecureChain'
ALGORITHM='HS256'
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
JWT_ACCESS_SECRET_KEY='your_access_secret_key'
JWT_REFRESH_SECRET_KEY='your_refresh_secret_key'
SECURE=False # Set to True in production
```
You can generate secure keys with:
```bash
openssl rand -base64 32
```

### 4. Build and run with Docker Compose as dev
```bash
docker-compose -f dev/docker-compose.yml up --build
```
This will build the backend and expose it on port 8001 (mapped to 8000 inside the container).

## API Overview

### Authentication Endpoints
- `POST /auth/signup` — Register a new user
- `POST /auth/login` — Login and receive access/refresh tokens
- `POST /auth/logout` — Logout and revoke refresh token
- `POST /auth/account_exists` — Check if an account exists
- `POST /auth/change_password` — Change user password
- `POST /auth/check_token` — Verify access token
- `POST /auth/refresh_token` — Refresh access token

### Health Check
- `GET /health` — Returns `{ "code": "healthy" }` if the service is running

## Testing

### Install test dependencies
```bash
pip install -r tests/requirements-dev.txt
```

### Run tests
```bash
pytest tests
```

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Links
- [Secure Chain Team](mailto:hi@securechain.dev)
- [Secure Chain Organization](https://github.com/securechaindev)