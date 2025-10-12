# Secure Chain Auth

A simple user registry backend for Secure Chain tools, built with FastAPI. This service provides user authentication, registration, password management, and token-based security, with support for MongoDB and Neo4j databases.

## Development requirements

1. [Docker](https://www.docker.com/) to deploy the tool.
2. [Docker Compose](https://docs.docker.com/compose/) for container orchestration.
3. It is recommended to use a GUI such as [MongoDB Compass](https://www.mongodb.com/en/products/compass).
4. Python 3.13 or higher.
5. [uv](https://github.com/astral-sh/uv) - Ultra-fast Python package manager (optional but recommended).

## Setup development profile

### 1. Clone the repository
```bash
git clone https://github.com/securechaindev/securechain-auth.git
cd securechain-auth
```

### 2. Configure environment variables
Create a `.env` file from the `template.env` file and place it in the `app/` directory. Modify the **Json Web Token (JWT)** secret key and algorithm with your own. You can generate your own secret key with the command **openssl rand -base64 32**.

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

## Python Environment
The project uses Python 3.13 and the dependencies are managed with `uv` (ultra-fast Python package manager).

### Setting up the development environment

#### Option 1: Using uv (Recommended)

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

4. **Install dev dependencies**:
   ```bash
   uv sync --extra dev
   # Or using pip-like syntax
   uv pip install ".[dev]"
   ```

#### Option 2: Using traditional venv + pip

1. **Create a virtual environment**:
   ```bash
   python3.13 -m venv auth-env
   ```

2. **Activate the virtual environment**:
   ```bash
   source auth-env/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install .
   # Or with dev dependencies
   pip install ".[dev]"
   ```

## Testing

### Install test dependencies

With uv:
```bash
uv sync --extra dev
# Or
uv pip install ".[dev]"
```

With pip:
```bash
pip install ".[dev]"
```

### Run tests
```bash
pytest tests
```

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
[GNU General Public License 3.0](https://www.gnu.org/licenses/gpl-3.0.html)

## Links
- [Secure Chain Team](mailto:hi@securechain.dev)
- [Secure Chain Organization](https://github.com/securechaindev)
- [Secure Chain Documentation](https://securechaindev.github.io/)