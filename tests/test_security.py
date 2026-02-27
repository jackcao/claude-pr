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
