# Secure Chain User Backend

A simple user registry backend for Secure Chain tools, built with FastAPI. This service provides user authentication, registration, password management, and token-based security, with support for MongoDB and Neo4j databases.

## Features
- User registration and login with JWT authentication
- Password change and validation (strong password policy)
- Token refresh and revocation (logout)
- Account existence check
- Health check endpoint
- Rate limiting on all endpoints
- MongoDB (via Odmantic) and Neo4j support
- Docker and docker-compose support
- Comprehensive test suite

## Requirements
- Python 3.10+
- MongoDB
- Neo4j
- (Optional) Docker & docker-compose

## Setup

### 1. Clone the repository
```bash
git clone <repo-url>
cd login_backend
```

### 2. Install dependencies
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables
Copy the template and fill in your secrets:
```bash
cp template.env .env
```
Edit `.env` with your database URIs, credentials, and JWT secrets. Example:
```
GRAPH_DB_URI='bolt://localhost:7687'
VULN_DB_URI='mongodb://mongoDepex:mongoDepex@localhost:27017/admin'
GRAPH_DB_USER='neo4j'
GRAPH_DB_PASSWORD='neoDepex'
VULN_DB_USER='mongoDepex'
VULN_DB_PASSWORD='mongoDepex'
ALGORITHM='HS256'
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
JWT_ACCESS_SECRET_KEY='your_access_secret_key'
JWT_REFRESH_SECRET_KEY='your_refresh_secret_key'
SECURE=False # Set to True in production
```
You can generate secure keys with:
```bash
openssl rand -base64 32
```

### 4. Run the server
```bash
uvicorn app.main:app --reload
```
The API will be available at `http://localhost:8000`.

## Docker

### Build and run with Docker Compose
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

### Example Request: Signup
```json
POST /auth/signup
{
  "email": "user@example.com",
  "password": "Str0ngP@ssw0rd!"
}
```

### Password Policy
- 8–20 characters
- At least one uppercase letter
- At least one digit
- At least one special character

### Email Format
- Must match: `^[\w\-.]+@([\w-]+\.)+[\w-]{2,4}$`

## Testing

### Install test dependencies
```bash
pip install -r tests/requirements-dev.txt
```

### Run tests
```bash
pytest
```

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
[GPLv3+](https://www.gnu.org/licenses/gpl-3.0.html)

## Contact
- SecureChain Team — [hi@securechain.dev](mailto:hi@securechain.dev)
- [https://github.com/securechaindev](https://github.com/securechaindev)