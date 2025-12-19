from datetime import datetime, timedelta
from sqlalchemy.orm import Session as DbSession
from models import Session, User
from utils import Validator
from crypto import crypto_manager
from config import settings
import logging

class SessionManager:
    def __init__(self, db: DbSession):
        self.db = db

    def create_session(self, user: User, user_agent: str, ip: str) -> tuple[str, str]:
        """
        Creates a new session with device binding.
        Returns (session_id_plaintext, refresh_token_plaintext)
        """
        # 1. Generate High Entropy ID
        session_token = Validator.generate_token(64)
        session_hash = Validator.hash_token(session_token)
        
        # 2. Generate Refresh Token
        refresh_token = Validator.generate_token(64)
        refresh_enc = crypto_manager.encrypt(refresh_token)
        
        # 3. Create Session Record
        new_session = Session(
            user_id=user.id,
            session_token_hash=session_hash,
            refresh_token_encrypted=refresh_enc,
            user_agent_hash=Validator.hash_user_agent(user_agent),
            ip_address=ip,
            expires_at=datetime.utcnow() + timedelta(seconds=settings.SESSION_LIFETIME_SECONDS),
            last_activity=datetime.utcnow()
        )
        
        self.db.add(new_session)
        self.db.commit()
        
        return session_token, refresh_token

    def validate_session(self, session_token: str, user_agent: str) -> Session:
        """
        Validates session exists, signature matches, not expired, not idle,
        and device fingerprint matches.
        """
        session_hash = Validator.hash_token(session_token)
        session = self.db.query(Session).filter_by(session_token_hash=session_hash).first()
        
        if not session:
            return None
            
        if session.is_revoked:
            return None
            
        # Absolute Timeout Check
        if datetime.utcnow() > session.expires_at:
            self.revoke_session(session)
            return None
            
        # Idle Timeout Check
        if datetime.utcnow() > session.last_activity + timedelta(seconds=settings.IDLE_TIMEOUT_SECONDS):
            self.revoke_session(session)
            return None
            
        # Device Binding Check (User Agent)
        if session.user_agent_hash != Validator.hash_user_agent(user_agent):
            # Potential Session Hijacking - Log this critically
            logging.warning(f"Session Hijack Attempt: ID {session.id} IP {session.ip_address}")
            self.revoke_session(session)
            return None
            
        # Update Idle Timer
        session.last_activity = datetime.utcnow()
        self.db.commit()
        return session

    def rotate_session(self, old_session: Session, new_ip: str) -> str:
        """
        Session Rotation: New ID, same state. Prevents Fixation.
        """
        new_token = Validator.generate_token(64)
        old_session.session_token_hash = Validator.hash_token(new_token)
        old_session.ip_address = new_ip # Update IP if changed (optional)
        self.db.commit()
        return new_token

    def revoke_session(self, session: Session):
        session.is_revoked = True
        self.db.delete(session) # Or mark revoked if keeping history
        self.db.commit()

    def revoke_all_user_sessions(self, user_id: str):
        """Panic Button / Password Reset / Security Breach"""
        sessions = self.db.query(Session).filter_by(user_id=user_id).all()
        for s in sessions:
            s.is_revoked = True
            self.db.delete(s)
        self.db.commit()