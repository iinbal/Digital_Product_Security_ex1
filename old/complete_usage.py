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