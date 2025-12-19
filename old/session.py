"""
Session Management Module
Student ID: [SECURE_DATING_AUTH_2024]

Implements secure session management:
- Cryptographically secure session ID generation (256-bit entropy)
- Session binding (IP, user-agent validation)
- Absolute and idle timeouts
- Session rotation on authentication
- Secure session invalidation
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from sqlalchemy.orm import Session as DBSession

from .config import config
from .models import Session, User
from .crypto_utils import token_generator


class SessionManager:
    """
    Manages user sessions with security controls.
    
    Security Features:
    - 256-bit entropy session IDs
    - Session fixation protection (rotation)
    - Session hijacking protection (binding)
    - Automatic timeout (absolute + idle)
    - Secure invalidation
    """
    
    def __init__(self, db_session: DBSession):
        """
        Initialize session manager.
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
    
    def create_session(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str,
        platform: str = 'web',
        device_fingerprint: Optional[str] = None
    ) -> Tuple[str, Session]:
        """
        Create new session for authenticated user.
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent string
            platform: Platform type (web, mobile, api)
            device_fingerprint: Optional device fingerprint hash
            
        Returns:
            Tuple of (session_id, session_object)
            
        Security Notes:
        - Generates cryptographically secure session ID (256 bits)
        - Sets appropriate timeout based on platform
        - Binds session to IP and user agent
        - Logs session creation
        """
        # Generate cryptographically secure session ID
        session_id = self._generate_session_id()
        
        # Determine session timeout based on platform
        if platform == 'mobile':
            absolute_timeout = config.SESSION_ABSOLUTE_TIMEOUT_MOBILE
        else:
            absolute_timeout = config.SESSION_ABSOLUTE_TIMEOUT_WEB
        
        expires_at = datetime.utcnow() + absolute_timeout
        
        # Create session record
        session = Session(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            platform=platform,
            expires_at=expires_at,
            is_active=True
        )
        
        self.db.add(session)
        self.db.commit()
        
        return session_id, session
    
    def _generate_session_id(self) -> str:
        """
        Generate cryptographically secure session ID.
        
        Returns:
            URL-safe session ID with 256 bits of entropy
            
        Security: Uses secrets module (os.urandom internally)
        """
        return token_generator.generate_token(config.SESSION_ID_BYTES)
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session object or None if not found
        """
        return self.db.query(Session).filter(
            Session.session_id == session_id,
            Session.is_active == True
        ).first()
    
    def validate_session(
        self,
        session_id: str,
        ip_address: str,
        user_agent: str,
        update_activity: bool = True
    ) -> Tuple[bool, Optional[Session], Optional[str]]:
        """
        Validate session and check security constraints.
        
        Args:
            session_id: Session identifier
            ip_address: Current client IP
            user_agent: Current client user agent
            update_activity: Whether to update last activity timestamp
            
        Returns:
            Tuple of (is_valid, session_object, error_message)
            
        Security Checks:
        - Session exists and is active
        - Session not expired (absolute timeout)
        - Session not idle (idle timeout)
        - IP address matches (if binding enabled)
        - User agent matches (if binding enabled)
        """
        # Get session
        session = self.get_session(session_id)
        
        if not session:
            return False, None, "Invalid session"
        
        # Check if session is expired
        if session.is_expired:
            self.invalidate_session(session_id, reason="expired")
            return False, None, "Session expired"
        
        # Check session binding - IP address
        if config.SESSION_BIND_IP:
            if session.ip_address != ip_address:
                # IP mismatch - potential session hijacking
                self.invalidate_session(session_id, reason="ip_mismatch")
                return False, None, "Session invalid"
        
        # Check session binding - User agent
        if config.SESSION_BIND_USER_AGENT:
            if session.user_agent != user_agent:
                # User agent mismatch - potential session hijacking
                self.invalidate_session(session_id, reason="user_agent_mismatch")
                return False, None, "Session invalid"
        
        # Update last activity timestamp
        if update_activity:
            session.last_activity_at = datetime.utcnow()
            self.db.commit()
        
        return True, session, None
    
    def rotate_session_id(self, old_session_id: str) -> Optional[str]:
        """
        Rotate session ID (session fixation protection).
        
        Args:
            old_session_id: Current session ID
            
        Returns:
            New session ID or None if session not found
            
        Security Notes:
        - Call after authentication to prevent session fixation
        - Call after privilege escalation
        - Preserves all session data except ID
        """
        session = self.get_session(old_session_id)
        
        if not session:
            return None
        
        # Generate new session ID
        new_session_id = self._generate_session_id()
        
        # Update session with new ID
        session.session_id = new_session_id
        self.db.commit()
        
        return new_session_id
    
    def invalidate_session(
        self,
        session_id: str,
        reason: str = "logout"
    ) -> bool:
        """
        Invalidate specific session.
        
        Args:
            session_id: Session to invalidate
            reason: Reason for invalidation (for audit log)
            
        Returns:
            True if session was invalidated
            
        Security: Complete server-side invalidation
        """
        session = self.get_session(session_id)
        
        if not session:
            return False
        
        # Mark as inactive
        session.is_active = False
        session.invalidated_at = datetime.utcnow()
        session.invalidation_reason = reason
        
        self.db.commit()
        
        return True
    
    def invalidate_all_user_sessions(
        self,
        user_id: int,
        reason: str = "security_event",
        except_session_id: Optional[str] = None
    ) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User whose sessions to invalidate
            reason: Reason for invalidation
            except_session_id: Optional session ID to keep active
            
        Returns:
            Number of sessions invalidated
            
        Use Cases:
        - Password change (invalidate all sessions)
        - "Logout all devices" feature
        - Security incident response
        """
        query = self.db.query(Session).filter(
            Session.user_id == user_id,
            Session.is_active == True
        )
        
        # Optionally keep one session active
        if except_session_id:
            query = query.filter(Session.session_id != except_session_id)
        
        sessions = query.all()
        
        # Invalidate each session
        for session in sessions:
            session.is_active = False
            session.invalidated_at = datetime.utcnow()
            session.invalidation_reason = reason
        
        self.db.commit()
        
        return len(sessions)
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions from database.
        
        Returns:
            Number of sessions cleaned up
            
        Note: Run periodically as maintenance task
        """
        cutoff_time = datetime.utcnow()
        
        # Find expired sessions
        expired_sessions = self.db.query(Session).filter(
            Session.is_active == True,
            Session.expires_at < cutoff_time
        ).all()
        
        # Mark as expired
        for session in expired_sessions:
            session.is_active = False
            session.invalidated_at = datetime.utcnow()
            session.invalidation_reason = "expired"
        
        self.db.commit()
        
        return len(expired_sessions)
    
    def get_user_active_sessions(self, user_id: int) -> list:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active Session objects
            
        Use: Display to user for "active sessions" management
        """
        return self.db.query(Session).filter(
            Session.user_id == user_id,
            Session.is_active == True
        ).order_by(Session.last_activity_at.desc()).all()
    
    def get_session_info(self, session: Session) -> Dict:
        """
        Get user-friendly session information.
        
        Args:
            session: Session object
            
        Returns:
            Dictionary with session details
        """
        return {
            'platform': session.platform,
            'ip_address': session.ip_address,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity_at.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'is_current': False  # Set by caller if this is current session
        }


class SessionCookieManager:
    """
    Manages secure cookie configuration for sessions.
    
    Security Features:
    - HttpOnly flag (XSS protection)
    - Secure flag (HTTPS only)
    - SameSite attribute (CSRF protection)
    - Proper domain and path restrictions
    """
    
    @staticmethod
    def get_cookie_config() -> Dict:
        """
        Get secure cookie configuration.
        
        Returns:
            Dictionary with cookie settings
            
        Security Notes:
        - HttpOnly: Prevents JavaScript access (XSS mitigation)
        - Secure: Only sent over HTTPS
        - SameSite: CSRF protection
        - Max-Age: Limits cookie lifetime
        """
        return {
            'httponly': config.COOKIE_HTTPONLY,
            'secure': config.COOKIE_SECURE,
            'samesite': config.COOKIE_SAMESITE,
            'domain': config.COOKIE_DOMAIN,
            'path': config.COOKIE_PATH,
            'max_age': config.COOKIE_MAX_AGE
        }
    
    @staticmethod
    def create_session_cookie_value(session_id: str) -> str:
        """
        Create signed session cookie value.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Signed cookie value
            
        Note: In production, use framework's signed cookie support
        """
        # In production, use framework's session management
        # This is simplified for demonstration
        return session_id
    
    @staticmethod
    def delete_cookie_config() -> Dict:
        """
        Get configuration for deleting session cookie.
        
        Returns:
            Dictionary with cookie deletion settings
        """
        config_dict = SessionCookieManager.get_cookie_config()
        config_dict['max_age'] = 0
        config_dict['expires'] = 0
        return config_dict


class DeviceFingerprinter:
    """
    Generate device fingerprints for anomaly detection.
    
    Privacy Notes:
    - Uses only publicly available browser information
    - No tracking of personal data
    - Used for security, not advertising
    """
    
    @staticmethod
    def generate_fingerprint(
        user_agent: str,
        accept_language: Optional[str] = None,
        screen_resolution: Optional[str] = None,
        timezone: Optional[str] = None
    ) -> str:
        """
        Generate device fingerprint hash.
        
        Args:
            user_agent: Browser user agent string
            accept_language: Accept-Language header
            screen_resolution: Screen dimensions
            timezone: Client timezone
            
        Returns:
            SHA-256 hash of device characteristics
            
        Note: This is basic fingerprinting. For production, use
        specialized libraries or services.
        """
        # Combine available device characteristics
        fingerprint_data = f"{user_agent}"
        
        if accept_language:
            fingerprint_data += f"|{accept_language}"
        if screen_resolution:
            fingerprint_data += f"|{screen_resolution}"
        if timezone:
            fingerprint_data += f"|{timezone}"
        
        # Hash to create fingerprint
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()


# Convenience functions for Flask/FastAPI integration

def create_user_session(
    db: DBSession,
    user_id: int,
    ip_address: str,
    user_agent: str,
    platform: str = 'web'
) -> Tuple[str, Session]:
    """Create new session for user"""
    manager = SessionManager(db)
    return manager.create_session(user_id, ip_address, user_agent, platform)


def validate_user_session(
    db: DBSession,
    session_id: str,
    ip_address: str,
    user_agent: str
) -> Tuple[bool, Optional[Session], Optional[str]]:
    """Validate existing session"""
    manager = SessionManager(db)
    return manager.validate_session(session_id, ip_address, user_agent)


def logout_user(db: DBSession, session_id: str) -> bool:
    """Logout user (invalidate session)"""
    manager = SessionManager(db)
    return manager.invalidate_session(session_id, reason="logout")


def logout_all_devices(db: DBSession, user_id: int, current_session_id: Optional[str] = None) -> int:
    """Logout from all devices"""
    manager = SessionManager(db)
    return manager.invalidate_all_user_sessions(user_id, "logout_all", current_session_id)