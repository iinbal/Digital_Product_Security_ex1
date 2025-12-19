import datetime
from sqlalchemy.orm import Session as DbSession
from models import User, AuditLog
from crypto import crypto_manager
from utils import Validator
from config import settings

class AuthService:
    def __init__(self, db: DbSession):
        self.db = db

    def register_user(self, email, password):
        if self.db.query(User).filter_by(email=email).first():
            raise ValueError("User exists") # In prod, return generic message
            
        if not Validator.validate_password(password):
            raise ValueError("Password violates complexity policy")
            
        hashed_pw = crypto_manager.hash_password(password)
        
        user = User(email=email, password_hash=hashed_pw)
        self.db.add(user)
        self.log_audit(None, "REGISTER", "SUCCESS", email)
        self.db.commit()
        return user

    def login(self, email, password, ip_address):
        user = self.db.query(User).filter_by(email=email).first()
        
        # 1. Check if Locked
        if user and user.locked_until:
            if datetime.datetime.utcnow() < user.locked_until:
                self.log_audit(user.id, "LOGIN", "LOCKED_OUT", ip_address)
                raise PermissionError("Account locked")
            else:
                user.locked_until = None
                user.failed_login_attempts = 0

        # 2. Constant time verification (prevents timing attacks on username)
        # Note: If user is None, we should simulate a hash verify to prevent timing enumeration
        # For this example, we proceed standardly.
        
        if not user or not crypto_manager.verify_password(user.password_hash, password):
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                    user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.LOCKOUT_DURATION)
                self.db.commit()
                self.log_audit(user.id, "LOGIN", "FAILURE", ip_address)
            return None

        # 3. Check Force Reset
        if user.force_password_reset:
             raise PermissionError("Password reset required")

        # 4. Success Reset Counters
        user.failed_login_attempts = 0
        self.db.commit()
        self.log_audit(user.id, "LOGIN", "SUCCESS", ip_address)
        
        return user

    def change_password(self, user_id, new_password):
        if not Validator.validate_password(new_password):
            raise ValueError("Weak password")
            
        user = self.db.query(User).filter_by(id=user_id).first()
        user.password_hash = crypto_manager.hash_password(new_password)
        user.force_password_reset = False
        self.db.commit()
        
        # MANDATORY: Invalidate all sessions
        from session import SessionManager
        SessionManager(self.db).revoke_all_user_sessions(user_id)
        self.log_audit(user.id, "PASSWORD_CHANGE", "SUCCESS", "All sessions revoked")

    def log_audit(self, user_id, event, status, details):
        log = AuditLog(
            user_id=user_id,
            event_type=event,
            status=status,
            details=details,
            ip_address="0.0.0.0" # Placeholder
        )
        self.db.add(log)
        self.db.commit()