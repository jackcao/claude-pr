# Claude PR API

A FastAPI-based authentication and user management API with JWT token support.

## Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- SQLite database with SQLAlchemy ORM
- Comprehensive test coverage
- Auto-generated API documentation

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd claude-pr
```

2. Install dependencies using uv:
```bash
uv sync
```

3. Create a `.env` file from the example:
```bash
cp .env.example .env
```

4. Update the `.env` file with your configuration (especially change `SECRET_KEY` in production).

## Running the Application

Start the development server:
```bash
uv run uvicorn app.main:app --reload
```

Or simply run:
```bash
uv run main.py
```

The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## API Endpoints

### Public Endpoints

- `GET /` - Root endpoint with API information
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login (OAuth2 form data)
- `POST /api/v1/auth/login/json` - Login (JSON format)

### Protected Endpoints (require authentication)

- `GET /api/v1/auth/me` - Get current user information

## Authentication

Protected endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <your-access-token>
```

## Testing

Run the test suite:
```bash
uv run pytest -v
```

Run tests with coverage:
```bash
uv run pytest --cov=app --cov-report=html
```

## Code Quality

Format code with Ruff:
```bash
uv run ruff format .
```

Check code with Ruff:
```bash
uv run ruff check .
```

## Environment Variables

See `.env.example` for all available configuration options:

- `SECRET_KEY` - Secret key for JWT token signing (required)
- `ALGORITHM` - JWT algorithm (default: HS256)
- `ACCESS_TOKEN_EXPIRE_MINUTES` - Token expiration time in minutes (default: 30)
- `DATABASE_URL` - Database connection string (default: sqlite:///./app.db)
- `APP_NAME` - Application name (default: Claude PR API)
- `VERSION` - Application version (default: 0.1.0)

## Project Structure

```
claude-pr/
├── app/
│   ├── api/
│   │   ├── deps.py          # Dependencies (authentication, database)
│   │   └── v1/
│   │       └── auth.py      # Authentication endpoints
│   ├── core/
│   │   ├── config.py        # Configuration settings
│   │   ├── database.py      # Database setup
│   │   └── security.py      # Security utilities (JWT, password hashing)
│   ├── crud/
│   │   └── user.py          # User CRUD operations
│   ├── main.py              # FastAPI application setup
│   ├── models/
│   │   └── user.py          # SQLAlchemy models
│   └── schemas/
│       ├── auth.py          # Authentication schemas
│       └── user.py          # User schemas
├── tests/
│   ├── api/
│   │   └── test_auth.py     # API endpoint tests
│   ├── test_config.py       # Configuration tests
│   ├── test_database.py     # Database tests
│   ├── test_deps.py         # Dependency tests
│   ├── test_main.py         # Main app tests
│   ├── test_schemas.py      # Schema validation tests
│   ├── test_security.py     # Security function tests
│   ├── test_user_crud.py    # User CRUD tests
│   └── test_user_model.py   # User model tests
├── .env.example             # Environment variables example
├── pyproject.toml           # Project configuration
├── ruff.toml               # Ruff configuration
└── main.py                 # Entry point
```

## License

MIT
