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


def test_decode_expired_token():
    """验证过期 token 解码失败"""
    from datetime import timedelta
    from app.core.security import create_access_token, decode_access_token

    # 创建一个已过期的 token (过期时间设为过去)
    data = {"sub": "testuser"}
    token = create_access_token(data, expires_delta=timedelta(seconds=-1))

    # 过期的 token 应该返回 None
    decoded = decode_access_token(token)
    assert decoded is None


def test_decode_invalid_token():
    """验证无效 token 解码失败"""
    from app.core.security import decode_access_token

    # 无效的 token 字符串
    invalid_token = "invalid.token.string"
    decoded = decode_access_token(invalid_token)
    assert decoded is None


def test_create_token_with_custom_expiration():
    """验证自定义过期时间的 token"""
    from datetime import timedelta
    from app.core.security import create_access_token, decode_access_token

    data = {"sub": "testuser"}
    # 创建 1 小时后过期的 token
    token = create_access_token(data, expires_delta=timedelta(hours=1))

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded.get("sub") == "testuser"
