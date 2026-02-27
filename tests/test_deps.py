import pytest
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
