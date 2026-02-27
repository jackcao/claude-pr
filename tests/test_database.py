from app.core.database import engine, get_db


def test_engine_exists():
    """验证数据库引擎已创建"""
    assert engine is not None


def test_get_db_generator():
    """验证 get_db 是生成器函数"""
    db_gen = get_db()
    assert hasattr(db_gen, "__iter__") or hasattr(db_gen, "__aiter__")
    # 清理
    db_gen.close()
