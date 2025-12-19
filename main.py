from flask import Flask, request, jsonify, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Session
from config import settings
from auth import AuthService
from session import SessionManager
from mfa import MFAService
from crypto import crypto_manager
import datetime

# --- SETUP ---
app = Flask(__name__)
engine = create_engine(settings.DATABASE_URL)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# --- MIDDLEWARE / HELPERS ---
def get_db():
    return SessionLocal()

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# --- ROUTES ---

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    db = get_db()
    auth = AuthService(db)
    try:
        auth.register_user(data['email'], data['password'])
        return jsonify({"msg": "User created. Please verify email."}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    finally:
        db.close()

@app.route('/login', methods=['POST'])
def login():
    """
    Step 1 of Login. 
    If MFA is enabled, returns a temp token to proceed to MFA verify.
    If not, sets session cookie.
    """
    data = request.json
    db = get_db()
    auth = AuthService(db)
    sm = SessionManager(db)
    
    try:
        user = auth.login(data['email'], data['password'], request.remote_addr)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
            
        if user.is_mfa_enabled:
            # Dating App: Require MFA for security
            return jsonify({"msg": "MFA Required", "next_step": "verify_mfa", "user_id": user.id}), 200
            
        # Create Session
        s_token, r_token = sm.create_session(user, request.headers.get('User-Agent'), request.remote_addr)
        
        resp = make_response(jsonify({"msg": "Login success"}))
        
        # SECURE COOKIE CONFIGURATION
        resp.set_cookie(
            'session_id', s_token,
            httponly=True,  # No JS access
            secure=True,    # HTTPS only
            samesite='Strict', # Prevent CSRF
            max_age=settings.SESSION_LIFETIME_SECONDS
        )
        return resp
        
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    finally:
        db.close()

@app.route('/sensitive/view_profile/<target_id>', methods=['GET'])
def view_dating_profile(target_id):
    """
    Example of Dating App specific logic:
    Checks session, checks scope, checks anti-stalking limits.
    """
    token = request.cookies.get('session_id')
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
        
    db = get_db()
    sm = SessionManager(db)
    session = sm.validate_session(token, request.headers.get('User-Agent'))
    
    if not session:
        return jsonify({"error": "Session invalid or expired"}), 401
        
    # PRIVACY CHECK: Is Identity Verified?
    if not session.user.is_identity_verified:
        return jsonify({"error": "Must verify identity to view full profiles"}), 403
        
    # ANTI-STALKING / RATE LIMIT
    # (Pseudocode implementation of logic)
    # count = db.query(ProfileView).filter(user=session.user, period="15min").count()
    # if count > 20: Panic...
    
    return jsonify({"profile": "Sensitive Data Here"})

@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('session_id')
    if token:
        db = get_db()
        sm = SessionManager(db)
        session = sm.validate_session(token, request.headers.get('User-Agent'))
        if session:
            sm.revoke_session(session)
        db.close()
        
    resp = make_response(jsonify({"msg": "Logged out"}))
    resp.delete_cookie('session_id')
    return resp

@app.route('/logout_all', methods=['POST'])
def panic_button():
    """Dating App Safety Feature: Panic Button"""
    # Requires re-authentication usually, or valid current session
    token = request.cookies.get('session_id')
    if not token: return jsonify({"error": "Auth required"}), 401
    
    db = get_db()
    sm = SessionManager(db)
    session = sm.validate_session(token, request.headers.get('User-Agent'))
    
    if session:
        sm.revoke_all_user_sessions(session.user_id)
        
    resp = make_response(jsonify({"msg": "All sessions terminated."}))
    resp.delete_cookie('session_id')
    return resp

if __name__ == "__main__":
    # In production, run with Gunicorn + SSL
    app.run(ssl_context='adhoc', debug=False)