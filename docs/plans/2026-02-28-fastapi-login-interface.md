# FastAPI 登录接口实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标:** 使用 FastAPI 框架实现用户登录接口，使用 SQLite 作为持久化数据库，支持用户注册、登录和基本的用户管理功能。

**架构:** 采用三层架构：API 层（FastAPI 路由）→ 业务逻辑层（services）→ 数据访问层（repository）。使用 Pydantic 进行数据验证，passlib 进行密码哈希，JWT 进行认证。

**技术栈:** FastAPI, SQLite, Pydantic, passlib, python-jose, pytest

---

## Task 1: 更新项目依赖

**文件:**
- 修改: `pyproject.toml`

**Step 1: 添加项目依赖**

编辑 `pyproject.toml`，在 `dependencies` 中添加所需的包：

```toml
[project]
name = "claude-pr"
version = "0.1.0"
description = "FastAPI Login Interface"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "sqlalchemy>=2.0.36",
    "pydantic>=2.10.0",
    "pydantic-settings>=2.6.0",
    "passlib[bcrypt]>=1.7.4",
    "python-jose[cryptography]>=3.3.0",
    "python-multipart>=0.0.17",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "httpx>=0.28.0",
    "ruff>=0.8.0",
]
```

**Step 2: 安装依赖**

Run: `uv sync --extra dev`
Expected: 所有依赖安装成功，无错误

**Step 3: 提交**

```bash
git add pyproject.toml uv.lock
git commit -m "feat: add FastAPI and auth dependencies"
```

---

## Task 2: 创建项目目录结构

**文件:**
- 创建: `app/__init__.py`
- 创建: `app/main.py`
- 创建: `app/models/__init__.py`
- 创建: `app/models/user.py`
- 创建: `app/schemas/__init__.py`
- 创建: `app/schemas/user.py`
- 创建: `app/schemas/auth.py`
- 创建: `app/core/__init__.py`
- 创建: `app/core/config.py`
- 创建: `app/core/security.py`
- 创建: `app/core/database.py`
- 创建: `app/api/__init__.py`
- 创建: `app/api/deps.py`
- 创建: `app/api/v1/__init__.py`
- 创建: `app/api/v1/auth.py`
- 创建: `app/crud/__init__.py`
- 创建: `app/crud/user.py`
- 创建: `tests/__init__.py`
- 创建: `tests/conftest.py`
- 创建: `tests/api/__init__.py`
- 创建: `tests/api/test_auth.py`

**Step 1: 创建目录结构**

Run:
```bash
mkdir -p app/{models,schemas,core,api/v1,crud}
mkdir -p tests/api
```

**Step 2: 创建 `__init__.py` 文件**

Run:
```bash
touch app/__init__.py app/models/__init__.py app/schemas/__init__.py app/core/__init__.py
touch app/api/__init__.py app/api/v1/__init__.py app/crud/__init__.py
touch tests/__init__.py tests/api/__init__.py
```

**Step 3: 提交**

```bash
git add app/ tests/
git commit -m "feat: create project directory structure"
```

---

## Task 3: 配置应用设置

**文件:**
- 创建: `app/core/config.py`
- 测试: `tests/test_config.py`

**Step 1: 编写配置测试**

创建 `tests/test_config.py`:

```python
import os
from app.core.config import settings


def test_settings_exist():
    """验证配置对象存在且包含必需字段"""
    assert hasattr(settings, 'SECRET_KEY')
    assert hasattr(settings, 'ALGORITHM')
    assert hasattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES')
    assert hasattr(settings, 'DATABASE_URL')


def test_default_values():
    """验证默认配置值"""
    assert settings.ALGORITHM == "HS256"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 30
    assert "test.db" in settings.DATABASE_URL
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL (ModuleNotFoundError 或 ImportError)

**Step 3: 实现配置模块**

创建 `app/core/config.py`:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Security
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    DATABASE_URL: str = "sqlite:///./test.db"

    # App
    APP_NAME: str = "Claude PR API"
    VERSION: str = "0.1.0"


settings = Settings()
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS

**Step 5: 提交**

```bash
git add app/core/config.py tests/test_config.py
git commit -m "feat: add application configuration"
```

---

## Task 4: 数据库连接设置

**文件:**
- 创建: `app/core/database.py`
- 测试: `tests/test_database.py`

**Step 1: 编写数据库测试**

创建 `tests/test_database.py`:

```python
from app.core.database import engine, get_db


def test_engine_exists():
    """验证数据库引擎已创建"""
    assert engine is not None


def test_get_db_generator():
    """验证 get_db 是生成器函数"""
    db_gen = get_db()
    assert hasattr(db_gen, '__iter__') or hasattr(db_gen, '__aiter__')
    # 清理
    db_gen.close()
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_database.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: 实现数据库模块**

创建 `app/core/database.py`:

```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency for getting DB session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/test_database.py -v`
Expected: PASS

**Step 5: 提交**

```bash
git add app/core/database.py tests/test_database.py
git commit -m "feat: add database connection setup"
```

---

## Task 5: 创建用户模型

**文件:**
- 创建: `app/models/user.py`
- 测试: `tests/test_user_model.py`

**Step 1: 编写模型测试**

创建 `tests/test_user_model.py`:

```python
from app.models.user import User
from sqlalchemy.orm import Session
from app.core.database import engine, Base


def test_user_table_creation():
    """验证用户表可以创建"""
    Base.metadata.create_all(bind=engine)
    # 如果没有异常，说明表创建成功
    assert True


def test_user_fields():
    """验证用户模型有正确的字段"""
    assert hasattr(User, 'id')
    assert hasattr(User, 'username')
    assert hasattr(User, 'email')
    assert hasattr(User, 'hashed_password')
    assert hasattr(User, 'is_active')
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_user_model.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: 实现用户模型**

创建 `app/models/user.py`:

```python
from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/test_user_model.py -v`
Expected: PASS

**Step 5: 提交**

```bash
git add app/models/user.py tests/test_user_model.py
git commit -m "feat: add user model"
```

---

## Task 6: 实现密码加密功能

**文件:**
- 创建: `app/core/security.py`
- 测试: `tests/test_security.py`

**Step 1: 编写安全功能测试**

创建 `tests/test_security.py`:

```python
from app.core.security import verify_password, get_password_hash


def test_password_hashing():
    """验证密码哈希和验证功能"""
    plain_password = "test123"
    hashed = get_password_hash(plain_password)

    # 哈希后的密码应该与原密码不同
    assert hashed != plain_password

    # 应该能正确验证密码
    assert verify_password(plain_password, hashed) is True


def test_wrong_password():
    """验证错误密码应该返回 False"""
    plain_password = "test123"
    wrong_password = "wrong123"
    hashed = get_password_hash(plain_password)

    assert verify_password(wrong_password, hashed) is False


def test_create_access_token():
    """验证 JWT token 创建"""
    from app.core.security import create_access_token

    data = {"sub": "testuser"}
    token = create_access_token(data)

    assert isinstance(token, str)
    assert len(token) > 0


def test_decode_access_token():
    """验证 JWT token 解码"""
    from app.core.security import create_access_token, decode_access_token

    data = {"sub": "testuser"}
    token = create_access_token(data)
    decoded = decode_access_token(token)

    assert decoded is not None
    assert decoded.get("sub") == "testuser"
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_security.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: 实现安全模块**

创建 `app/core/security.py`:

```python
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """生成密码哈希"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """创建 JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """解码 JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/test_security.py -v`
Expected: PASS

**Step 5: 提交**

```bash
git add app/core/security.py tests/test_security.py
git commit -m "feat: add password hashing and JWT token functions"
```

---

## Task 7: 创建 Pydantic Schemas

**文件:**
- 创建: `app/schemas/user.py`
- 创建: `app/schemas/auth.py`
- 测试: `tests/test_schemas.py`

**Step 1: 编写 Schema 测试**

创建 `tests/test_schemas.py`:

```python
from pydantic import ValidationError
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import Token, LoginRequest


def test_user_create_valid():
    """验证有效的用户创建数据"""
    data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123"
    }
    user = UserCreate(**data)
    assert user.username == "testuser"
    assert user.email == "test@example.com"


def test_user_create_invalid_email():
    """验证无效的邮箱应该失败"""
    data = {
        "username": "testuser",
        "email": "invalid-email",
        "password": "testpass123"
    }
    try:
        UserCreate(**data)
        assert False, "应该抛出 ValidationError"
    except ValidationError:
        assert True


def test_login_request():
    """验证登录请求 schema"""
    data = {
        "username": "testuser",
        "password": "testpass123"
    }
    login = LoginRequest(**data)
    assert login.username == "testuser"


def test_token_response():
    """验证 Token 响应 schema"""
    data = {
        "access_token": "test_token_value",
        "token_type": "bearer"
    }
    token = Token(**data)
    assert token.access_token == "test_token_value"
    assert token.token_type == "bearer"
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_schemas.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: 实现 User Schemas**

创建 `app/schemas/user.py`:

```python
from pydantic import BaseModel, EmailStr, ConfigDict


class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool
```

**Step 4: 实现 Auth Schemas**

创建 `app/schemas/auth.py`:

```python
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: str | None = None
```

**Step 5: 运行测试确认通过**

Run: `uv run pytest tests/test_schemas.py -v`
Expected: PASS

**Step 6: 提交**

```bash
git add app/schemas/ tests/test_schemas.py
git commit -m "feat: add pydantic schemas for user and auth"
```

---

## Task 8: 实现用户 CRUD 操作

**文件:**
- 创建: `app/crud/user.py`
- 测试: `tests/test_user_crud.py`

**Step 1: 编写 CRUD 测试**

创建 `tests/test_user_crud.py`:

```python
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.database import Base
from app.crud.user import user_crud
from app.schemas.user import UserCreate
from app.models.user import User


# 使用内存数据库进行测试
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture
def test_db():
    """创建测试数据库"""
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_create_user(test_db):
    """测试创建用户"""
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )
    user = user_crud.create(test_db, user_data)
    assert user.id is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.is_active is True


def test_get_user_by_username(test_db):
    """测试通过用户名获取用户"""
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.get_by_username(test_db, "testuser")
    assert user is not None
    assert user.username == "testuser"


def test_get_user_by_email(test_db):
    """测试通过邮箱获取用户"""
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.get_by_email(test_db, "test@example.com")
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_user_success(test_db):
    """测试成功的用户认证"""
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.authenticate(test_db, "testuser", "testpass123")
    assert user is not None
    assert user.username == "testuser"


def test_authenticate_user_wrong_password(test_db):
    """测试错误密码的认证"""
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.authenticate(test_db, "testuser", "wrongpass")
    assert user is None
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_user_crud.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: 实现用户 CRUD**

创建 `app/crud/user.py`:

```python
from typing import Optional
from sqlalchemy.orm import Session

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate


class CRUDUser:
    def get(self, db: Session, id: int) -> Optional[User]:
        """通过 ID 获取用户"""
        return db.query(User).filter(User.id == id).first()

    def get_by_username(self, db: Session, username: str) -> Optional[User]:
        """通过用户名获取用户"""
        return db.query(User).filter(User.username == username).first()

    def get_by_email(self, db: Session, email: str) -> Optional[User]:
        """通过邮箱获取用户"""
        return db.query(User).filter(User.email == email).first()

    def create(self, db: Session, obj_in: UserCreate) -> User:
        """创建新用户"""
        db_obj = User(
            username=obj_in.username,
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def authenticate(
        self, db: Session, username: str, password: str
    ) -> Optional[User]:
        """验证用户"""
        user = self.get_by_username(db, username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user


user_crud = CRUDUser()
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/test_user_crud.py -v`
Expected: PASS

**Step 5: 提交**

```bash
git add app/crud/user.py tests/test_user_crud.py
git commit -m "feat: add user CRUD operations"
```

---

## Task 9: 实现认证依赖

**文件:**
- 创建: `app/api/deps.py`
- 测试: `tests/test_deps.py`

**Step 1: 编写依赖测试**

创建 `tests/test_deps.py`:

```python
import pytest
from fastapi import Depends
from app.api.deps import get_current_user
from app.core.security import create_access_token
from app.schemas.user import UserCreate
from app.crud.user import user_crud
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.database import Base


TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture
def test_db():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_get_current_user_valid_token(test_db):
    """测试有效 token 获取用户"""
    # 创建测试用户
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )
    user = user_crud.create(test_db, user_data)

    # 创建 token
    token = create_access_token(data={"sub": user.username})

    # 注意：这个测试需要 FastAPI TestClient，后续在 API 测试中完善
    assert token is not None
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_deps.py -v`
Expected: FAIL (ModuleNotFoundError)

**Step 3: 实现认证依赖**

创建 `app/api/deps.py`:

```python
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.crud.user import user_crud
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """获取当前认证用户"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception

    user = user_crud.get_by_username(db, username=username)
    if user is None:
        raise credentials_exception

    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """获取当前活跃用户"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/test_deps.py -v`
Expected: PASS (注意：完整测试需要 FastAPI TestClient，在下一个任务中实现)

**Step 5: 提交**

```bash
git add app/api/deps.py tests/test_deps.py
git commit -m "feat: add authentication dependencies"
```

---

## Task 10: 实现登录 API

**文件:**
- 创建: `app/api/v1/auth.py`
- 测试: `tests/api/test_auth.py`

**Step 1: 编写登录 API 测试**

创建 `tests/api/test_auth.py`:

```python
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.database import Base, get_db
from app.main import app
from app.schemas.user import UserCreate
from app.crud.user import user_crud


TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture
def test_db():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(test_db):
    """创建测试客户端"""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_register_user(client):
    """测试用户注册"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert "password" not in data  # 不应该返回密码


def test_register_duplicate_username(client):
    """测试重复用户名注册失败"""
    # 第一次注册
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123"
        }
    )

    # 第二次注册相同用户名
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "another@example.com",
            "password": "testpass123"
        }
    )
    assert response.status_code == 400


def test_login_success(client):
    """测试成功登录"""
    # 先注册用户
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123"
        }
    )

    # 登录
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "testuser",
            "password": "testpass123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client):
    """测试错误密码登录失败"""
    # 先注册用户
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123"
        }
    )

    # 错误密码登录
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "testuser",
            "password": "wrongpass"
        }
    )
    assert response.status_code == 401


def test_login_nonexistent_user(client):
    """测试不存在用户登录失败"""
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "nonexistent",
            "password": "testpass123"
        }
    )
    assert response.status_code == 401


def test_get_me_without_token(client):
    """测试无 token 访问受保护路由"""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_get_me_with_valid_token(client):
    """测试有效 token 访问受保护路由"""
    # 注册并登录
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123"
        }
    )
    login_response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "testuser",
            "password": "testpass123"
        }
    )
    token = login_response.json()["access_token"]

    # 访问受保护路由
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/api/test_auth.py -v`
Expected: FAIL (ModuleNotFoundError 或路由不存在)

**Step 3: 实现认证路由**

创建 `app/api/v1/auth.py`:

```python
from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token
from app.crud.user import user_crud
from app.models.user import User
from app.schemas.auth import Token, LoginRequest
from app.schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)) -> Any:
    """
    用户注册

    - **username**: 用户名（唯一）
    - **email**: 邮箱地址（唯一）
    - **password**: 密码
    """
    # 检查用户名是否已存在
    user_by_username = user_crud.get_by_username(db, username=user_in.username)
    if user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名已被注册"
        )

    # 检查邮箱是否已存在
    user_by_email = user_crud.get_by_email(db, email=user_in.email)
    if user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="邮箱已被注册"
        )

    # 创建新用户
    user = user_crud.create(db, obj_in=user_in)
    return user


@router.post("/login", response_model=Token)
def login(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    用户登录（OAuth2 兼容）

    使用 form-data 格式：
    - **username**: 用户名
    - **password**: 密码

    返回 JWT access token
    """
    user = user_crud.authenticate(
        db, username=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login/json", response_model=Token)
def login_json(login_data: LoginRequest, db: Session = Depends(get_db)) -> Any:
    """
    用户登录（JSON 格式）

    使用 JSON 格式：
    - **username**: 用户名
    - **password**: 密码

    返回 JWT access token
    """
    user = user_crud.authenticate(
        db, username=login_data.username, password=login_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
) -> Any:
    """
    获取当前用户信息

    需要在 Header 中提供有效的 JWT token：
    Authorization: Bearer <token>
    """
    return current_user
```

**Step 4: 运行测试确认通过**

Run: `uv run pytest tests/api/test_auth.py -v`
Expected: FAIL (FastAPI app 还没有配置路由)

**Step 5: 提交（暂时）**

```bash
git add app/api/v1/auth.py tests/api/test_auth.py
git commit -m "feat: add authentication API routes"
```

---

## Task 11: 创建 FastAPI 主应用

**文件:**
- 修改: `app/main.py`
- 更新: `main.py` (项目根目录)

**Step 1: 编写应用启动测试**

创建 `tests/test_main.py`:

```python
from fastapi.testclient import TestClient
from app.main import app


def test_app_exists():
    """验证应用存在"""
    assert app is not None


def test_root_endpoint():
    """测试根端点"""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "Welcome to Claude PR API"


def test_health_check():
    """测试健康检查端点"""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_api_docs():
    """测试 API 文档可访问"""
    client = TestClient(app)
    response = client.get("/docs")
    assert response.status_code == 200
```

**Step 2: 运行测试确认失败**

Run: `uv run pytest tests/test_main.py -v`
Expected: FAIL (应用未正确配置)

**Step 3: 实现主应用**

创建 `app/main.py`:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import auth
from app.core.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="FastAPI Login Interface",
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(auth.router, prefix="/api/v1")


@app.get("/", tags=["Root"])
def read_root():
    """根端点"""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.VERSION,
        "docs": "/docs"
    }


@app.get("/health", tags=["Health"])
def health_check():
    """健康检查"""
    return {"status": "healthy", "version": settings.VERSION}
```

**Step 4: 更新根目录 main.py**

编辑 `main.py` (项目根目录):

```python
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
```

**Step 5: 运行测试确认通过**

Run: `uv run pytest tests/test_main.py -v`
Expected: PASS

**Step 6: 运行 API 测试确认通过**

Run: `uv run pytest tests/api/test_auth.py -v`
Expected: PASS

**Step 7: 提交**

```bash
git add app/main.py main.py tests/test_main.py
git commit -m "feat: create FastAPI main application"
```

---

## Task 12: 添加 Ruff 配置

**文件:**
- 创建: `ruff.toml`

**Step 1: 创建 Ruff 配置**

创建 `ruff.toml`:

```toml
[lint]
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # Pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade
]
ignore = [
    "E501",  # line too long
]

[format]
quote-style = "double"
indent-style = "space"
```

**Step 2: 运行 Ruff 检查**

Run: `uv run ruff check .`
Expected: 无错误或仅有格式问题

**Step 3: 运行 Ruff 格式化**

Run: `uv run ruff format .`

**Step 4: 提交**

```bash
git add ruff.toml
git commit -m "chore: add ruff configuration"
```

---

## Task 13: 创建 .env.example 文件

**文件:**
- 创建: `.env.example`

**Step 1: 创建环境变量示例文件**

创建 `.env.example`:

```
# Security
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=sqlite:///./app.db

# App
APP_NAME=Claude PR API
VERSION=0.1.0
```

**Step 2: 提交**

```bash
git add .env.example
git commit -m "chore: add environment variables example"
```

---

## Task 14: 更新 .gitignore

**文件:**
- 修改: `.gitignore`

**Step 1: 添加数据库文件到 gitignore**

在 `.gitignore` 文件末尾添加：

```
# Database
*.db
*.db-journal
.env
```

**Step 2: 提交**

```bash
git add .gitignore
git commit -m "chore: add database files to gitignore"
```

---

## Task 15: 更新 README

**文件:**
- 修改: `README.md`

**Step 1: 更新 README 内容**

编辑 `README.md`:

```markdown
# Claude PR API

基于 FastAPI 的用户认证 API。

## 功能

- 用户注册
- 用户登录（JWT 认证）
- 获取当前用户信息
- SQLite 数据库持久化

## 快速开始

### 安装依赖

```bash
uv sync --extra dev
```

### 运行应用

```bash
# 开发模式
uv run python main.py

# 或直接使用 uvicorn
uv run uvicorn app.main:app --reload
```

API 将在 `http://localhost:8000` 启动。

### API 文档

启动应用后访问：
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## 运行测试

```bash
# 运行所有测试
uv run pytest

# 运行特定测试文件
uv run pytest tests/api/test_auth.py -v

# 查看覆盖率
uv run pytest --cov=app --cov-report=html
```

## 代码检查

```bash
# Ruff 检查
uv run ruff check .

# Ruff 格式化
uv run ruff format .
```

## API 端点

### 认证

- `POST /api/v1/auth/register` - 用户注册
- `POST /api/v1/auth/login` - 用户登录（OAuth2 form-data）
- `POST /api/v1/auth/login/json` - 用户登录（JSON）
- `GET /api/v1/auth/me` - 获取当前用户信息（需要认证）

### 其他

- `GET /` - 欢迎页面
- `GET /health` - 健康检查

## 环境变量

复制 `.env.example` 到 `.env` 并根据需要修改：

```bash
cp .env.example .env
```
```

**Step 2: 提交**

```bash
git add README.md
git commit -m "docs: update README with API documentation"
```

---

## Task 16: 最终集成测试

**Step 1: 运行所有测试**

Run:
```bash
uv run pytest -v
```

Expected: 所有测试通过

**Step 2: 启动应用验证**

Run:
```bash
uv run python main.py
```

验证以下操作：
1. 访问 `http://localhost:8000/docs` 查看 API 文档
2. 使用 `/api/v1/auth/register` 注册用户
3. 使用 `/api/v1/auth/login` 登录获取 token
4. 使用 token 访问 `/api/v1/auth/me`

**Step 3: 代码检查和格式化**

Run:
```bash
uv run ruff check .
uv run ruff format .
```

**Step 4: 提交所有更新**

```bash
git add -A
git commit -m "test: all tests passing, application ready"
```

---

## 完成

实现完成后，项目结构如下：

```
claude-pr/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI 应用
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py             # 认证依赖
│   │   └── v1/
│   │       ├── __init__.py
│   │       └── auth.py         # 认证路由
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py           # 配置
│   │   ├── database.py         # 数据库连接
│   │   └── security.py         # 密码哈希和 JWT
│   ├── crud/
│   │   ├── __init__.py
│   │   └── user.py             # 用户 CRUD
│   ├── models/
│   │   ├── __init__.py
│   │   └── user.py             # 用户模型
│   └── schemas/
│       ├── __init__.py
│       ├── auth.py             # 认证 schemas
│       └── user.py             # 用户 schemas
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # pytest fixtures
│   ├── api/
│   │   ├── __init__.py
│   │   └── test_auth.py        # API 测试
│   ├── test_config.py
│   ├── test_database.py
│   ├── test_deps.py
│   ├── test_main.py
│   ├── test_schemas.py
│   ├── test_security.py
│   └── test_user_crud.py
├── docs/
│   └── plans/
│       └── 2026-02-28-fastapi-login-interface.md
├── main.py                     # 应用入口
├── pyproject.toml
├── ruff.toml
├── .env.example
└── README.md
```
