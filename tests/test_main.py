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
