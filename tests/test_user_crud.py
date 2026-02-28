import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.crud.user import user_crud
from app.schemas.user import UserCreate

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
        username="testuser", email="test@example.com", password="testpass123"
    )
    user = user_crud.create(test_db, user_data)
    assert user.id is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.is_active is True


def test_get_user_by_username(test_db):
    """测试通过用户名获取用户"""
    user_data = UserCreate(
        username="testuser", email="test@example.com", password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.get_by_username(test_db, "testuser")
    assert user is not None
    assert user.username == "testuser"


def test_get_user_by_email(test_db):
    """测试通过邮箱获取用户"""
    user_data = UserCreate(
        username="testuser", email="test@example.com", password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.get_by_email(test_db, "test@example.com")
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_user_success(test_db):
    """测试成功的用户认证"""
    user_data = UserCreate(
        username="testuser", email="test@example.com", password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.authenticate(test_db, "testuser", "testpass123")
    assert user is not None
    assert user.username == "testuser"


def test_authenticate_user_wrong_password(test_db):
    """测试错误密码的认证"""
    user_data = UserCreate(
        username="testuser", email="test@example.com", password="testpass123"
    )
    user_crud.create(test_db, user_data)

    user = user_crud.authenticate(test_db, "testuser", "wrongpass")
    assert user is None
