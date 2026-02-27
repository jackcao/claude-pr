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
