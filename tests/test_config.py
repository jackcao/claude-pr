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
