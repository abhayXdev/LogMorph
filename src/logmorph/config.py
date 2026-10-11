from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    PROJECT_NAME: str = "LogMorph API"
    ENVIRONMENT: str = "development"

    # Database Settings
    # Use postgresql+asyncpg:// for NeonDB or sqlite+aiosqlite:/// for local dev/testing
    DATABASE_URL: str = "sqlite+aiosqlite:///./logmorph_dev.db"

    # Authentication
    SECRET_KEY: str = "change_this_in_production_secret_key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # LLM Settings
    NVIDIA_NIM_API_KEY: Optional[str] = None
    NVIDIA_NIM_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    LLM_MODEL: str = "meta/llama3-70b-instruct"

    # Apache Kafka Settings (Serverless Upstash or Local)
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC_RAW_LOGS: str = "raw-logs"
    KAFKA_SASL_USERNAME: Optional[str] = None
    KAFKA_SASL_PASSWORD: Optional[str] = None
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT"  # Use "SASL_SSL" with Upstash Kafka
    KAFKA_SASL_MECHANISM: str = "PLAIN"  # Use "SCRAM-SHA-256" with Upstash Kafka

    # Redis (Upstash — Deduplication & Caching)
    REDIS_URL: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
