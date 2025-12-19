import datetime
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey, Text, Enum
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
import enum

Base = declarative_base()

class UserRole(enum.Enum):
    USER = "user"
    VERIFIED = "verified" # ID Verified
    MODERATOR = "moderator"
    ADMIN = "admin"

class User(Base):
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    
    # Security Columns
    password_hash = Column(String(255), nullable=False)
    mfa_secret = Column(String(255), nullable=True) # Encrypted
    is_mfa_enabled = Column(Boolean, default=False)
    
    # Verification & Dating Context
    is_email_verified = Column(Boolean, default=False)
    is_identity_verified = Column(Boolean, default=False) # Photo ID check
    age_verified = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    
    # Brute Force Protection
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # Breach Response
    force_password_reset = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    sessions = relationship("Session", back_populates="user", cascade="all, delete")

class Session(Base):
    __tablename__ = 'sessions'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    
    # Session Security
    session_token_hash = Column(String(64), unique=True, nullable=False) # SHA-256 of the actual token
    refresh_token_encrypted = Column(Text, nullable=True) # AES-256 Encrypted
    
    # Device Binding
    ip_address = Column(String(45))
    user_agent_hash = Column(String(64)) # Hash of UA string
    device_fingerprint = Column(String(64))
    
    # Lifecycle
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False) # Absolute timeout
    last_activity = Column(DateTime, default=func.now()) # Idle timeout
    is_revoked = Column(Boolean, default=False)
    
    # Privacy & Consent Scope (Dating Specific)
    scope_location_access = Column(Boolean, default=False)
    scope_sensitive_media = Column(Boolean, default=False)

    user = relationship("User", back_populates="sessions")

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=func.now())
    user_id = Column(String(36), nullable=True)
    event_type = Column(String(50), nullable=False)
    ip_address = Column(String(45))
    details = Column(Text)
    status = Column(String(20)) # SUCCESS / FAILURE