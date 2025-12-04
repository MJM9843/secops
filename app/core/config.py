# File: backend/app/core/config.py

from pydantic_settings import BaseSettings
from typing import List
import secrets

class Settings(BaseSettings):
    APP_NAME: str = "SecOps"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = secrets.token_urlsafe(32)
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5000"]
    LOG_LEVEL: str = "INFO"
    
    # AWS Regions
    AWS_REGIONS: List[str] = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    
    # Session Configuration
    SESSION_TIMEOUT: int = 3600  # 1 hour in seconds
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
