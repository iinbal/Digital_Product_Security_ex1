""
Authentication Module
Complete user authentication with security controls
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict
from sqlalchemy.orm import Session as DBSession
import hashlib

from .config import config
from .models import User, VerificationToken, LoginAttempt, AuditLog
from .crypto_utils import hash_password, verify_password, generate_secure_token
from .password_policy import validate_password
from .mfa import verify_mfa_token
from .rate_limiter import RateLimiter
from .email_service import send_verification_email, send_password_reset_email
from .session import SessionManager


class AuthenticationManager:
    """Complete authentication management with security controls"""
    
    def __init__(self, db_session: DBSession):
        self.db = db_session
        self.rate_limiter = RateLimiter(db_session)
        self.session_manager = SessionManager(db_session)
    
    def register_user(
        self,
        email: str,
        password: str,
        date_of_birth: datetime,
        ip_address: str,
        additional_data: Dict = None
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Register new user with validation and email verification.
        
        Security Checks:
        - Email uniqueness
        - Password policy validation
        - Age verification (18+)
        - Rate limiting on registration
        """
        # Normalize email
        email = email.lower().strip()
        
        # Check rate limiting
        if not self.rate_limiter.check_rate_limit('registration', ip_address):
            return False, None, "Too many registration attempts. Please try again later."
        
        # Check if email already exists
        existing_user = self.db.query(User).filter(User.email == email).first()
        if existing_user:
            return False, None, "Email already registered"
        
        # Validate password policy
        is_valid, errors = validate_password(password, {'email': email})
        if not is_valid:
            return False, None, '; '.join(errors)
        
        # Validate age (18+)
        age = (datetime.utcnow() - date_of_birth).days // 365
        if age < config.MINIMUM_AGE:
            return False, None, f"Must be at least {config.MINIMUM_AGE} years old"
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create user
        user = User(
            email=email,
            password_hash=password_hash,
            date_of_birth=date_of_birth,
            is_active=True,
            is_email_verified=False,
            role='user'
        )
        
        self.db.add(user)
        self.db.commit()
        
        # Generate verification token
        verification_token = self._create_verification_token(user.id, 'email_verification')
        
        # Send verification email (non-blocking in production)
        try:
            send_verification_email(user.email, verification_token)
        except Exception:
            # Log error but don't expose to user
            pass
        
        # Audit log
        self._log_event(user.id, 'user_registration', 'authentication', ip_address)
        
        return True, user, None
    
    def authenticate_user(
        self,
        email: str,
        password: str,
        mfa_token: Optional[str],
        ip_address: str,
        user_agent: str
    ) -> Tuple[bool, Optional[User], Optional[str], Optional[str]]:
        """
        Authenticate user with password and optional MFA.
        
        Returns:
            (success, user, session_id, error_message)
        """
        email = email.lower().strip()
        
        # Check account-level rate limiting
        if not self.rate_limiter.check_rate_limit('login', email):
            return False, None, None, "Too many login attempts. Account temporarily locked."
        
        # Check IP-level rate limiting
        if not self.rate_limiter.check_rate_limit('login_ip', ip_address):
            return False, None, None, "Too many login attempts from this location."
        
        # Get user
        user = self.db.query(User).filter(User.email == email).first()
        
        if not user:
            self._record_failed_login(None, email, ip_address, user_agent, 'user_not_found')
            return False, None, None, "Invalid email or password"
        
        # Check if account is locked
        if user.is_account_locked:
            self._record_failed_login(user.id, email, ip_address, user_agent, 'account_locked')
            return False, None, None, "Account is temporarily locked. Please try again later."
        
        # Verify password
        if not verify_password(user.password_hash, password):
            self._record_failed_login(user.id, email, ip_address, user_agent, 'invalid_password')
            self.rate_limiter.record_failed_attempt('login', email)
            return False, None, None, "Invalid email or password"
        
        # Check MFA if enabled
        if user.mfa_enabled:
            if not mfa_token:
                return False, None, None, "MFA token required"
            
            if not verify_mfa_token(user.mfa_secret, mfa_token):
                self._record_failed_login(user.id, email, ip_address, user_agent, 'mfa_failed')
                return False, None, None, "Invalid MFA token"
        
        # Authentication successful - create session
        session_id, session = self.session_manager.create_session(
            user.id,
            ip_address,
            user_agent,
            platform='web'
        )
        
        # Update user login timestamp
        user.last_login_at = datetime.utcnow()
        self.db.commit()
        
        # Record successful login
        self._record_successful_login(user.id, email, ip_address, user_agent)
        
        # Reset rate limiter for successful login
        self.rate_limiter.reset_rate_limit('login', email)
        
        # Audit log
        self._log_event(user.id, 'login_success', 'authentication', ip_address)
        
        return True, user, session_id, None
    
    def verify_email(self, token: str) -> Tuple[bool, Optional[str]]:
        """Verify email with verification token"""
        # Hash token for lookup
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        verification = self.db.query(VerificationToken).filter(
            VerificationToken.token_hash == token_hash,
            VerificationToken.token_type == 'email_verification'
        ).first()
        
        if not verification or not verification.is_valid:
            return False, "Invalid or expired verification token"
        
        # Mark token as used
        verification.used_at = datetime.utcnow()
        
        # Verify user email
        user = self.db.query(User).filter(User.id == verification.user_id).first()
        if user:
            user.is_email_verified = True
            if user.role == 'user':
                user.role = 'verified'  # Upgrade to verified role
        
        self.db.commit()
        
        return True, None
    
    def request_password_reset(
        self,
        email: str,
        ip_address: str
    ) -> Tuple[bool, Optional[str]]:
        """Request password reset token"""
        email = email.lower().strip()
        
        # Rate limiting
        if not self.rate_limiter.check_rate_limit('password_reset', email):
            return False, "Too many password reset requests. Please try again later."
        
        user = self.db.query(User).filter(User.email == email).first()
        
        # Always return success to prevent email enumeration
        if not user:
            return True, None
        
        # Generate reset token
        reset_token = self._create_verification_token(user.id, 'password_reset')
        
        # Send reset email (non-blocking)
        try:
            send_password_reset_email(user.email, reset_token)
        except Exception:
            # Non-descriptive response on email failure
            pass
        
        self.rate_limiter.record_failed_attempt('password_reset', email)
        self._log_event(user.id, 'password_reset_requested', 'security', ip_address)
        
        return True, None
    
    def reset_password(
        self,
        token: str,
        new_password: str,
        ip_address: str
    ) -> Tuple[bool, Optional[str]]:
        """Reset password with token"""
        # Hash token for lookup
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        verification = self.db.query(VerificationToken).filter(
            VerificationToken.token_hash == token_hash,
            VerificationToken.token_type == 'password_reset'
        ).first()
        
        if not verification or not verification.is_valid:
            return False, "Invalid or expired reset token"
        
        # Get user
        user = self.db.query(User).filter(User.id == verification.user_id).first()
        if not user:
            return False, "User not found"
        
        # Validate new password
        is_valid, errors = validate_password(new_password, {'email': user.email})
        if not is_valid:
            return False, '; '.join(errors)
        
        # Hash and update password
        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.utcnow()
        
        # Mark token as used
        verification.used_at = datetime.utcnow()
        
        # Invalidate ALL user sessions (force re-authentication)
        self.session_manager.invalidate_all_user_sessions(
            user.id,
            reason='password_reset'
        )
        
        self.db.commit()
        
        # Audit log
        self._log_event(user.id, 'password_reset_completed', 'security', ip_address)
        
        return True, None
    
    def _create_verification_token(self, user_id: int, token_type: str) -> str:
        """Create verification/reset token"""
        # Generate secure token
        token = generate_secure_token(config.EMAIL_VERIFICATION_TOKEN_BYTES)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Set expiration
        if token_type == 'email_verification':
            expires_at = datetime.utcnow() + config.EMAIL_VERIFICATION_TOKEN_EXPIRES
        else:  # password_reset
            expires_at = datetime.utcnow() + config.PASSWORD_RESET_TOKEN_EXPIRES
        
        # Create token record
        verification = VerificationToken(
            token_hash=token_hash,
            user_id=user_id,
            token_type=token_type,
            expires_at=expires_at
        )
        
        self.db.add(verification)
        self.db.commit()
        
        return token
    
    def _record_failed_login(self, user_id, email, ip_address, user_agent, reason):
        """Record failed login attempt"""
        attempt = LoginAttempt(
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason=reason
        )
        self.db.add(attempt)
        self.db.commit()
    
    def _record_successful_login(self, user_id, email, ip_address, user_agent):
        """Record successful login"""
        attempt = LoginAttempt(
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        self.db.add(attempt)
        self.db.commit()
    
    def _log_event(self, user_id, event_type, category, ip_address, metadata=None):
        """Create audit log entry"""
        log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_category=category,
            ip_address=ip_address,
            metadata=metadata
        )
        self.db.add(log)
        self.db.commit()