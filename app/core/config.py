from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Security
    # WARNING: This is a default SECRET_KEY for development/testing purposes only.
    # In production, ALWAYS override this with a strong, randomly generated key via environment variable.
    # Never use this default key in production environments as it is a well-known example from documentation.
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    DATABASE_URL: str = "sqlite:///./test.db"

    # App
    APP_NAME: str = "Claude PR API"
    VERSION: str = "0.1.0"


settings = Settings()
