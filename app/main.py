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
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """健康检查"""
    return {"status": "healthy", "version": settings.VERSION}
