import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database — shared RDS from cloud-security-platform-infra
    db_host:     str = os.getenv("DB_HOST", "localhost")
    db_port:     int = int(os.getenv("DB_PORT", "5432"))
    db_name:     str = os.getenv("DB_NAME", "cloud_security_platform")
    db_user:     str = os.getenv("DB_USER", "platform_admin")
    db_password: str = os.getenv("DB_PASSWORD", "")

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    # AWS
    aws_region:               str = os.getenv("AWS_REGION", "us-east-1")
    bedrock_model_id:         str = "anthropic.claude-3-sonnet-20240229-v1:0"
    bedrock_embedding_model_id: str = "amazon.titan-embed-text-v2:0"

    # OpenRouter fallback
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_model:   str = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")

    # S3
    s3_cache_bucket: str = os.getenv("S3_CACHE_BUCKET", "")

    # Collector interval
    collector_interval_minutes: int = 15

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
