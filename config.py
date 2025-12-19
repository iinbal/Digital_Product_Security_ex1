import os
from pydantic_settings import BaseSettings
from pydantic import Field

class SecurityConfig(BaseSettings):
    """
    Centralized security configuration loading from Environment Variables.
    Strictly forbids hardcoded secrets.
    """
    # Student Identity
    STUDENT_ID: str = Field(default="206539496_212047195", frozen=True)
    
    # Cryptography Keys
    SECRET_KEY: str = Field(..., min_length=64, description="Used for Flask/Session signing")
    JWT_SIGNING_KEY: str = Field(..., min_length=64, description="HMAC-SHA256 key for JWTs")
    DATA_ENCRYPTION_KEY: str = Field(..., min_length=32, description="AES-256 Key (Base64 encoded)")
    
    # Database
    DATABASE_URL: str = Field(default="sqlite:///dating_secure.db")
    
    # Policy Configuration
    SESSION_LIFETIME_SECONDS: int = 28800  # 8 Hours
    IDLE_TIMEOUT_SECONDS: int = 1800       # 30 Minutes
    JWT_ACCESS_LIFETIME: int = 900         # 15 Minutes
    JWT_REFRESH_LIFETIME: int = 604800     # 7 Days
    
    # Rate Limiting
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION: int = 1800           # 30 Minutes
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = SecurityConfig()