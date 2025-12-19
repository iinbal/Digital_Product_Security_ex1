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