# Complete Authentication & Session Management Library
## Student ID: [SECURE_DATING_AUTH_2024]
## Dating Platform Security Implementation

---

## TABLE OF CONTENTS
1. Authentication Module (auth.py)
2. JWT Token Management (jwt_auth.py)
3. Rate Limiting & Brute Force Protection
4. Audit Logging Module
5. Email Service Module
6. Complete Usage Examples
7. Database Schema (SQL)
8. Requirements.txt
9. Architecture Documentation
10. Security Design Decisions
11. Integration Guide
12. Dating Platform Specific Features

---

## 1. AUTHENTICATION MODULE (auth.py)

```python
"""
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
```

---

## 2. JWT TOKEN MANAGEMENT (jwt_auth.py)

```python
"""
JWT Token Management for API/Mobile Authentication
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict
import hashlib

from .config import config
from .models import RefreshToken, User
from .crypto_utils import generate_secure_token


class JWTManager:
    """Manages JWT access and refresh tokens"""
    
    def __init__(self, db_session):
        self.db = db_session
        self.secret_key = config.JWT_SECRET_KEY
        self.algorithm = config.JWT_ALGORITHM
    
    def create_access_token(self, user_id: int, role: str) -> str:
        """Create short-lived access token"""
        payload = {
            'user_id': user_id,
            'role': role,
            'type': 'access',
            'exp': datetime.utcnow() + config.JWT_ACCESS_TOKEN_EXPIRES,
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str
    ) -> str:
        """Create long-lived refresh token"""
        # Generate token
        token = generate_secure_token(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Create token family for rotation tracking
        token_family = generate_secure_token(16)
        
        # Store in database
        refresh_token = RefreshToken(
            token_hash=token_hash,
            user_id=user_id,
            token_family=token_family,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + config.JWT_REFRESH_TOKEN_EXPIRES
        )
        
        self.db.add(refresh_token)
        self.db.commit()
        
        return token
    
    def verify_access_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """Verify and decode access token"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            
            if payload.get('type') != 'access':
                return False, None
            
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, None
        except jwt.InvalidTokenError:
            return False, None
    
    def refresh_access_token(
        self,
        refresh_token: str,
        ip_address: str,
        user_agent: str
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Refresh access token using refresh token.
        Implements token rotation.
        
        Returns: (success, new_access_token, new_refresh_token, error)
        """
        # Hash token for lookup
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Find token
        db_token = self.db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash
        ).first()
        
        if not db_token or not db_token.is_valid:
            # Token reuse detected - revoke entire family
            if db_token:
                self._revoke_token_family(db_token.token_family)
            return False, None, None, "Invalid refresh token"
        
        # Get user
        user = self.db.query(User).filter(User.id == db_token.user_id).first()
        if not user or not user.is_active:
            return False, None, None, "Invalid user"
        
        # Revoke old token
        db_token.is_revoked = True
        db_token.revoked_at = datetime.utcnow()
        
        # Create new tokens
        new_access_token = self.create_access_token(user.id, user.role)
        
        if config.JWT_REFRESH_TOKEN_ROTATE:
            new_refresh_token = self.create_refresh_token(
                user.id,
                ip_address,
                user_agent
            )
        else:
            new_refresh_token = refresh_token
        
        self.db.commit()
        
        return True, new_access_token, new_refresh_token, None
    
    def _revoke_token_family(self, token_family: str):
        """Revoke all tokens in a family (token reuse detected)"""
        tokens = self.db.query(RefreshToken).filter(
            RefreshToken.token_family == token_family
        ).all()
        
        for token in tokens:
            token.is_revoked = True
            token.revoked_at = datetime.utcnow()
            token.revocation_reason = "token_reuse_detected"
        
        self.db.commit()
```

---

## 3. RATE LIMITING (rate_limiter.py)

```python
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
```

---

## 4. EMAIL SERVICE (email_service.py)

```python
"""
Email Service for Authentication Notifications
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from .config import config


def send_email(to_email: str, subject: str, body_html: str):
    """Send email (non-descriptive error handling)"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = config.EMAIL_FROM
        msg['To'] = to_email
        
        html_part = MIMEText(body_html, 'html')
        msg.attach(html_part)
        
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            if config.SMTP_USE_TLS:
                server.starttls()
            if config.SMTP_USERNAME and config.SMTP_PASSWORD:
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            server.send_message(msg)
    except Exception:
        # Non-descriptive response on failure
        pass


def send_verification_email(to_email: str, token: str):
    """Send email verification"""
    verify_url = f"https://yourdomain.com/verify-email?token={token}"
    
    body = f"""
    <h2>Welcome to SecureDating!</h2>
    <p>Please verify your email address by clicking the link below:</p>
    <p><a href="{verify_url}">Verify Email</a></p>
    <p>This link expires in 24 hours.</p>
    """
    
    send_email(to_email, "Verify Your Email", body)


def send_password_reset_email(to_email: str, token: str):
    """Send password reset email"""
    reset_url = f"https://yourdomain.com/reset-password?token={token}"
    
    body = f"""
    <h2>Password Reset Request</h2>
    <p>Click the link below to reset your password:</p>
    <p><a href="{reset_url}">Reset Password</a></p>
    <p>This link expires in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    """
    
    send_email(to_email, "Reset Your Password", body)
```

---

## 5. REQUIREMENTS.TXT

```
# Core framework (choose one)
Flask==2.3.0
# OR
fastapi==0.104.0
uvicorn==0.24.0

# Database
SQLAlchemy==2.0.23
psycopg2-binary==2.9.9  # PostgreSQL
# OR
pymysql==1.1.0  # MySQL

# Password hashing
argon2-cffi==23.1.0

# Cryptography
cryptography==41.0.7

# JWT
PyJWT==2.8.0

# MFA (TOTP)
pyotp==2.9.0
qrcode[pil]==7.4.2

# Rate limiting
python-dateutil==2.8.2

# Environment variables
python-dotenv==1.0.0

# Testing
pytest==7.4.3
pytest-cov==4.1.0
```

---

## 6. DATABASE SCHEMA (SQL)

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_locked BOOLEAN DEFAULT FALSE,
    locked_until TIMESTAMP,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(32),
    mfa_backup_codes TEXT,
    role VARCHAR(50) DEFAULT 'user',
    date_of_birth TIMESTAMP,
    age_verified BOOLEAN DEFAULT FALSE,
    profile_visibility VARCHAR(20) DEFAULT 'public',
    location_sharing_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_active ON users(is_active);
CREATE INDEX idx_user_role ON users(role);

-- Sessions table
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    device_fingerprint VARCHAR(64),
    platform VARCHAR(20) DEFAULT 'web',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    invalidated_at TIMESTAMP,
    invalidation_reason VARCHAR(100)
);

CREATE INDEX idx_session_id ON sessions(session_id);
CREATE INDEX idx_session_user ON sessions(user_id);
CREATE INDEX idx_session_active ON sessions(is_active);

-- All other tables follow the models.py structure
```

---

## 7. COMPLETE USAGE EXAMPLE

```python
"""
Complete Usage Example - Dating Platform Authentication
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from auth_library import (
    init_database,
    AuthenticationManager,
    SessionManager,
    JWTManager,
    setup_mfa_for_user,
    config
)

# Initialize database
engine = create_engine(config.DATABASE_URL)
init_database()
Session = sessionmaker(bind=engine)

# Example 1: User Registration
def register_new_user():
    db = Session()
    auth_manager = AuthenticationManager(db)
    
    success, user, error = auth_manager.register_user(
        email="john@example.com",
        password="SecureP@ssw0rd123!",
        date_of_birth=datetime(1990, 1, 15),
        ip_address="192.168.1.1"
    )
    
    if success:
        print(f"User registered: {user.email}")
        print("Verification email sent")
    else:
        print(f"Registration failed: {error}")
    
    db.close()

# Example 2: Login with MFA
def login_user():
    db = Session()
    auth_manager = AuthenticationManager(db)
    
    success, user, session_id, error = auth_manager.authenticate_user(
        email="john@example.com",
        password="SecureP@ssw0rd123!",
        mfa_token="123456",  # From authenticator app
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0..."
    )
    
    if success:
        print(f"Login successful! Session: {session_id}")
        # Set session cookie
        # response.set_cookie('session_id', session_id, **cookie_config)
    else:
        print(f"Login failed: {error}")
    
    db.close()

# Example 3: Password Reset Flow
def password_reset_flow():
    db = Session()
    auth_manager = AuthenticationManager(db)
    
    # Step 1: Request reset
    success, error = auth_manager.request_password_reset(
        email="john@example.com",
        ip_address="192.168.1.1"
    )
    
    # Step 2: User receives email with token, submits new password
    token = "received_from_email"
    success, error = auth_manager.reset_password(
        token=token,
        new_password="NewSecureP@ssw0rd456!",
        ip_address="192.168.1.1"
    )
    
    if success:
        print("Password reset successful")
    
    db.close()

# Example 4: Setup MFA
def setup_user_mfa():
    secret, uri, qr_code = setup_mfa_for_user("john@example.com")
    
    print(f"MFA Secret: {secret}")
    print(f"QR Code: <img src='data:image/png;base64,{qr_code}'>")
    
    # User scans QR code, enters first token to confirm
    # Then save encrypted secret to user.mfa_secret

# Example 5: API Authentication with JWT
def api_authentication():
    db = Session()
    jwt_manager = JWTManager(db)
    
    # After successful login, create tokens
    access_token = jwt_manager.create_access_token(user_id=1, role='verified')
    refresh_token = jwt_manager.create_refresh_token(
        user_id=1,
        ip_address="192.168.1.1",
        user_agent="Mobile App"
    )
    
    print(f"Access Token: {access_token}")
    print(f"Refresh Token: {refresh_token}")
    
    # When access token expires, refresh it
    success, new_access, new_refresh, error = jwt_manager.refresh_access_token(
        refresh_token=refresh_token,
        ip_address="192.168.1.1",
        user_agent="Mobile App"
    )
    
    db.close()
```

---

## 8. ARCHITECTURE & SECURITY DOCUMENTATION

### Threat Model for Dating Platform

**Primary Threats:**
1. **Account Takeover**: Credential stuffing, phishing, session hijacking
2. **Data Breach**: Unauthorized access to user profiles, messages