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
