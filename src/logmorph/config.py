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
    NVIDIA_NIM_API_KEY: str | None = None
    NVIDIA_NIM_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    LLM_MODEL: str = "meta/llama3-70b-instruct"

    # Apache Kafka Settings (Aiven Cloud Free Tier, Managed Kafka, or Local)
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC_RAW_LOGS: str = "raw-logs"
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT"  # Use "SSL" for Aiven mTLS or "SASL_SSL" for SASL

    # Aiven mTLS Certificate File Paths
    KAFKA_SSL_CAFILE: str | None = None
    KAFKA_SSL_CERTFILE: str | None = None
    KAFKA_SSL_KEYFILE: str | None = None

    # Base64/Raw Certificate strings for cloud deployments (e.g. Render)
    KAFKA_SSL_CA_CERT: str | None = None
    KAFKA_SSL_CLIENT_CERT: str | None = None
    KAFKA_SSL_CLIENT_KEY: str | None = None

    # SASL Settings (optional alternative)
    KAFKA_SASL_USERNAME: str | None = None
    KAFKA_SASL_PASSWORD: str | None = None
    KAFKA_SASL_MECHANISM: str = "PLAIN"

    # Redis (Upstash — Deduplication & Caching)
    REDIS_URL: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
