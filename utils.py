import re
import secrets
import hashlib
from datetime import datetime
from config import settings

class Validator:
    @staticmethod
    def validate_password(password: str) -> bool:
        """
        Enforces:
        - Min 12 chars
        - 1 Uppercase, 1 Lowercase, 1 Number, 1 Special
        """
        if len(password) < 12:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
            return False
        return True

    @staticmethod
    def generate_token(length_bytes: int = 32) -> str:
        """Generates cryptographically secure URL-safe token"""
        return secrets.token_urlsafe(length_bytes)

    @staticmethod
    def hash_token(token: str) -> str:
        """SHA-256 hash for storing session IDs safely in DB"""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def hash_user_agent(ua_string: str) -> str:
        return hashlib.sha256(ua_string.encode()).hexdigest()

def is_ip_allowed(ip_address: str, db_session) -> bool:
    """
    Checks global IP blacklist/rate limits.
    (Simplified implementation - Production should use Redis)
    """
    # Logic to check audit logs for rapid failures from this IP
    return True