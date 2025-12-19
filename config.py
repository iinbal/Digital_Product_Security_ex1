"""
Configuration Module for Dating Platform Authentication System
Student ID: [SECURE_DATING_AUTH_2024]

This module manages all security configuration parameters.
CRITICAL: Load all secrets from environment variables in production.
"""

import os
from datetime import timedelta
from typing import Dict, Any


class SecurityConfig:
    """
    Central configuration class for authentication and session management.
    All security-critical parameters are defined here with secure defaults.
    """
    
    # ==================== CRYPTOGRAPHIC SETTINGS ====================
    
    # CRITICAL: Load from environment variables - NEVER hardcode in production
    # These are examples only - replace with secure key management
    SECRET_KEY = os.getenv('APP_SECRET_KEY', 'CHANGE_IN_PRODUCTION_USE_ENV_VAR')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'CHANGE_IN_PRODUCTION_USE_ENV_VAR')
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'CHANGE_IN_PRODUCTION_USE_ENV_VAR')
    
    # Argon2id parameters - memory-hard KDF resistant to GPU attacks
    ARGON2_TIME_COST = 3  # Number of iterations
    ARGON2_MEMORY_COST = 65536  # 64 MB memory usage
    ARGON2_PARALLELISM = 4  # Number of parallel threads
    ARGON2_HASH_LENGTH = 32  # Output hash length in bytes
    ARGON2_SALT_LENGTH = 16  # Salt length in bytes
    
    # AES-256-GCM encryption settings
    AES_KEY_SIZE = 32  # 256 bits
    AES_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    
    # ==================== PASSWORD POLICY ====================
    
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Common password list check (implement with external breach database)
    CHECK_COMMON_PASSWORDS = True
    
    # ==================== SESSION MANAGEMENT ====================
    
    # Session timeouts - absolute maximum session lifetime
    SESSION_ABSOLUTE_TIMEOUT_WEB = timedelta(hours=8)
    SESSION_ABSOLUTE_TIMEOUT_MOBILE = timedelta(days=30)  # Longer for mobile
    
    # Idle timeout - time of inactivity before session expires
    SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
    
    # Session ID entropy - 256 bits minimum
    SESSION_ID_BYTES = 32  # 256 bits of entropy
    
    # Session binding to prevent session hijacking
    SESSION_BIND_IP = True  # Validate IP address hasn't changed
    SESSION_BIND_USER_AGENT = True  # Validate user agent consistency
    
    # ==================== JWT TOKEN SETTINGS ====================
    
    # Access token lifetime - short-lived
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    
    # Refresh token lifetime - longer but revocable
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    
    # JWT algorithm - use asymmetric for better security in production
    JWT_ALGORITHM = 'HS256'  # Use RS256 with public/private keys in production
    
    # Token rotation - enforce one-time use of refresh tokens
    JWT_REFRESH_TOKEN_ROTATE = True
    
    # ==================== COOKIE SECURITY ====================
    
    # Cookie flags for session cookies
    COOKIE_SECURE = True  # HTTPS only - disable for local dev
    COOKIE_HTTPONLY = True  # Prevent JavaScript access (XSS protection)
    COOKIE_SAMESITE = 'Strict'  # CSRF protection (Lax for some OAuth flows)
    COOKIE_DOMAIN = None  # Set to your domain in production
    COOKIE_PATH = '/'
    COOKIE_MAX_AGE = int(SESSION_ABSOLUTE_TIMEOUT_WEB.total_seconds())
    
    # ==================== BRUTE FORCE PROTECTION ====================
    
    # Account-level rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_ATTEMPT_WINDOW = timedelta(minutes=15)
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)
    
    # IP-based rate limiting for distributed attacks
    MAX_IP_LOGIN_ATTEMPTS = 20  # Higher threshold for shared IPs
    IP_RATE_LIMIT_WINDOW = timedelta(minutes=15)
    
    # Failed login tracking duration
    FAILED_LOGIN_RETENTION = timedelta(days=30)
    
    # ==================== MFA SETTINGS ====================
    
    # TOTP settings (RFC 6238)
    TOTP_INTERVAL = 30  # Time step in seconds
    TOTP_DIGITS = 6  # Number of digits in OTP
    TOTP_ALGORITHM = 'sha1'  # Standard TOTP uses SHA1 (not for hashing passwords)
    TOTP_ISSUER = 'SecureDating'  # App name in authenticator
    
    # Backup codes
    MFA_BACKUP_CODE_COUNT = 10
    MFA_BACKUP_CODE_LENGTH = 8
    
    # Enforce MFA for sensitive operations
    MFA_REQUIRED_FOR_PASSWORD_RESET = True
    MFA_REQUIRED_FOR_PRIVACY_SETTINGS = True
    MFA_REQUIRED_FOR_PAYMENT = True
    
    # ==================== ACCOUNT VERIFICATION ====================
    
    # Email verification token settings
    EMAIL_VERIFICATION_TOKEN_EXPIRES = timedelta(hours=24)
    EMAIL_VERIFICATION_TOKEN_BYTES = 32  # 256 bits entropy
    
    # Password reset token settings
    PASSWORD_RESET_TOKEN_EXPIRES = timedelta(hours=1)
    PASSWORD_RESET_TOKEN_BYTES = 32  # 256 bits entropy
    
    # Rate limiting for account operations
    MAX_PASSWORD_RESET_REQUESTS = 3
    PASSWORD_RESET_RATE_LIMIT_WINDOW = timedelta(hours=1)
    
    MAX_EMAIL_VERIFICATION_REQUESTS = 5
    EMAIL_VERIFICATION_RATE_LIMIT_WINDOW = timedelta(hours=1)
    
    # ==================== CAPTCHA SETTINGS ====================
    
    # Trigger CAPTCHA after failed login attempts
    CAPTCHA_AFTER_FAILED_ATTEMPTS = 3
    
    # CAPTCHA provider settings (configure based on provider)
    CAPTCHA_ENABLED = True
    RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY', '')
    RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY', '')
    
    # ==================== DATING PLATFORM SPECIFIC ====================
    
    # Privacy protection settings
    PROFILE_VIEW_RATE_LIMIT = 100  # Max profile views per hour
    MESSAGE_SEND_RATE_LIMIT = 50  # Max messages per hour
    MATCH_REQUEST_RATE_LIMIT = 30  # Max match requests per hour
    
    # Location privacy settings
    LOCATION_TOKEN_EXPIRES = timedelta(minutes=5)  # Short-lived location access
    REQUIRE_ACTIVE_SESSION_FOR_LOCATION = True
    
    # Age verification
    MINIMUM_AGE = 18
    REQUIRE_AGE_VERIFICATION = True
    
    # Sensitive data access logging
    LOG_PROFILE_VIEWS = True
    LOG_LOCATION_ACCESS = True
    LOG_CONTACT_INFO_ACCESS = True
    
    # Abuse prevention
    RAPID_ACCOUNT_CREATION_THRESHOLD = 3  # Accounts from same IP in 24h
    SUSPICIOUS_LOGIN_PATTERN_THRESHOLD = 5  # Different locations in 1 hour
    
    # ==================== AUDIT LOGGING ====================
    
    # Log retention policies
    AUDIT_LOG_RETENTION = timedelta(days=90)
    SECURITY_EVENT_LOG_RETENTION = timedelta(days=365)
    
    # What to log
    LOG_AUTHENTICATION_EVENTS = True
    LOG_SESSION_EVENTS = True
    LOG_MFA_EVENTS = True
    LOG_SENSITIVE_DATA_ACCESS = True
    
    # ==================== DATABASE SETTINGS ====================
    
    # Connection settings (load from environment)
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///dating_auth.db')
    
    # Connection pool settings for production
    DATABASE_POOL_SIZE = 20
    DATABASE_MAX_OVERFLOW = 10
    
    # ==================== EMAIL SETTINGS ====================
    
    # SMTP configuration (load from environment)
    SMTP_HOST = os.getenv('SMTP_HOST', 'localhost')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    SMTP_USE_TLS = True
    
    # Email addresses
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'noreply@securedating.com')
    EMAIL_SUPPORT = os.getenv('EMAIL_SUPPORT', 'support@securedating.com')
    
    # Email rate limiting
    MAX_EMAILS_PER_HOUR = 5
    
    # ==================== RBAC SETTINGS ====================
    
    # Role hierarchy for dating platform
    ROLES = {
        'user': 1,           # Regular user
        'verified': 2,       # Email/photo verified user
        'premium': 3,        # Premium subscriber
        'moderator': 10,     # Content moderator
        'admin': 100         # System administrator
    }
    
    # Permission levels for different operations
    MIN_ROLE_FOR_MESSAGING = 'verified'
    MIN_ROLE_FOR_LOCATION_SHARING = 'verified'
    MIN_ROLE_FOR_ADVANCED_SEARCH = 'premium'


class DevelopmentConfig(SecurityConfig):
    """Development configuration - less strict for testing"""
    COOKIE_SECURE = False  # Allow HTTP in development
    SESSION_BIND_IP = False  # Don't validate IP in dev (localhost changes)
    

class ProductionConfig(SecurityConfig):
    """Production configuration - maximum security"""
    # Enforce all security features
    COOKIE_SECURE = True
    SESSION_BIND_IP = True
    SESSION_BIND_USER_AGENT = True
    CAPTCHA_ENABLED = True
    
    # Shorter timeouts in production
    SESSION_IDLE_TIMEOUT = timedelta(minutes=20)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=10)


# Configuration selector based on environment
def get_config() -> SecurityConfig:
    """
    Returns appropriate configuration based on environment.
    Default to production for safety.
    """
    env = os.getenv('FLASK_ENV', 'production')
    if env == 'development':
        return DevelopmentConfig()
    return ProductionConfig()


# Export the active configuration
config = get_config()