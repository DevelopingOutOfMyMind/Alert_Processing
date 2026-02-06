"""
Configuration management for Alert Processing System.
"""
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration using Pydantic Settings."""
    
    # Application Settings
    app_name: str = "Alert Processing System"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    
    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_version: str = "v1"
    
    # Azure Settings
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    azure_log_analytics_workspace_id: Optional[str] = None
    
    # OpenAI Settings
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4-turbo-preview"
    openai_temperature: float = 0.1
    openai_max_tokens: int = 1000
    
    # Database Settings
    database_url: str = "sqlite:///alerts.db"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    
    # Redis Settings
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = 10
    
    # Alert Processing Settings
    max_concurrent_alerts: int = 10
    alert_retention_days: int = 30
    max_enrichment_retries: int = 3
    pii_anonymization_enabled: bool = True
    
    # Monitoring Settings
    enable_metrics: bool = True
    enable_tracing: bool = True
    jaeger_endpoint: str = "http://localhost:14268/api/traces"
    
    # Presidio Settings
    presidio_nlp_engine: str = "spacy"
    presidio_model_path: str = "en_core_web_sm"
    anonymize_with_fake_data: bool = False
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()