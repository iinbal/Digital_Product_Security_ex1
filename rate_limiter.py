"""
Rate Limiting and Brute Force Protection
"""

from datetime import datetime, timedelta
from .models import RateLimitTracker
from .config import config


class RateLimiter:
    """Rate limiting for various operations"""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def check_rate_limit(self, limit_type: str, key: str) -> bool:
        """
        Check if operation is within rate limit.
        
        Args:
            limit_type: Type of limit (login, password_reset, etc.)
            key: Identifier (email, IP address, user_id)
        
        Returns:
            True if within limit, False if exceeded
        """
        # Get rate limit configuration
        max_attempts, window = self._get_limit_config(limit_type)
        
        # Find existing tracker
        tracker = self.db.query(RateLimitTracker).filter(
            RateLimitTracker.limit_key == key,
            RateLimitTracker.limit_type == limit_type
        ).first()
        
        now = datetime.utcnow()
        
        if not tracker:
            # Create new tracker
            tracker = RateLimitTracker(
                limit_key=key,
                limit_type=limit_type,
                attempt_count=0,
                window_start=now,
                window_end=now + window
            )
            self.db.add(tracker)
            self.db.commit()
            return True
        
        # Check if window has expired
        if now > tracker.window_end:
            # Reset window
            tracker.attempt_count = 0
            tracker.window_start = now
            tracker.window_end = now + window
            self.db.commit()
            return True
        
        # Check if within limit
        return tracker.attempt_count < max_attempts
    
    def record_failed_attempt(self, limit_type: str, key: str):
        """Record a failed attempt"""
        tracker = self.db.query(RateLimitTracker).filter(
            RateLimitTracker.limit_key == key,
            RateLimitTracker.limit_type == limit_type
        ).first()
        
        if tracker:
            tracker.attempt_count += 1
            tracker.last_attempt_at = datetime.utcnow()
            self.db.commit()
    
    def reset_rate_limit(self, limit_type: str, key: str):
        """Reset rate limit (e.g., after successful login)"""
        tracker = self.db.query(RateLimitTracker).filter(
            RateLimitTracker.limit_key == key,
            RateLimitTracker.limit_type == limit_type
        ).first()
        
        if tracker:
            self.db.delete(tracker)
            self.db.commit()
    
    def _get_limit_config(self, limit_type: str) -> tuple:
        """Get max attempts and window for limit type"""
        configs = {
            'login': (config.MAX_LOGIN_ATTEMPTS, config.LOGIN_ATTEMPT_WINDOW),
            'login_ip': (config.MAX_IP_LOGIN_ATTEMPTS, config.IP_RATE_LIMIT_WINDOW),
            'password_reset': (config.MAX_PASSWORD_RESET_REQUESTS, config.PASSWORD_RESET_RATE_LIMIT_WINDOW),
            'profile_view': (config.PROFILE_VIEW_RATE_LIMIT, timedelta(hours=1)),
            'message_send': (config.MESSAGE_SEND_RATE_LIMIT, timedelta(hours=1)),
        }
        
        return configs.get(limit_type, (10, timedelta(hours=1)))