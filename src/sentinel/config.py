from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated application configuration for SentinelAI."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SENTINEL_",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "testing", "production"] = "development"
    debug: bool = False

    log_level: Literal[
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ] = "INFO"

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)

    llm_provider: Literal[
        "ollama",
        "openai",
        "disabled",
    ] = "disabled"

    llm_model: str = "qwen3:8b"


@lru_cache
def get_settings() -> Settings:
    """Return the cached SentinelAI configuration."""

    return Settings()