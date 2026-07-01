from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = "postgresql+asyncpg://vibesafe:vibesafe_dev@localhost:5432/vibesafe"
    test_database_url: str = "postgresql+asyncpg://vibesafe:vibesafe_dev@localhost:5432/vibesafe_test"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # LLM API Keys
    groq_api_key: str = ""
    openai_api_key: str = ""
    google_api_key: str = ""

    # App
    secret_key: str = "dev-secret-key-change-in-production"
    environment: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # GitHub
    github_token: str = ""

    # Scan limits
    max_repo_size_mb: int = 150
    max_files_per_scan: int = 500
    scan_timeout_seconds: int = 120

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def allowed_origins(self) -> list[str]:
        if self.is_production:
            return ["https://vibesafe.dev"]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
