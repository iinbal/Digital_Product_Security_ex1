"""
Multi-Factor Authentication (MFA) Module
Student ID: [SECURE_DATING_AUTH_2024]

Implements TOTP-based MFA (Time-based One-Time Password):
- QR code generation for authenticator apps
- TOTP validation (6-digit codes)
- Backup code generation and validation
- MFA enforcement for sensitive operations
"""

import pyotp
import qrcode
import io
import base64
from typing import List, Tuple, Optional
from datetime import datetime

from .config import config
from .crypto_utils import token_generator, password_hasher


class MFAManager:
    """
    Manages TOTP-based two-factor authentication.
    
    Compatible with: Google Authenticator, Authy, Microsoft Authenticator, etc.
    Uses RFC 6238 TOTP standard with 30-second time windows.
    """
    
    def __init__(self):
        self.issuer = config.TOTP_ISSUER
        self.interval = config.TOTP_INTERVAL
        self.digits = config.TOTP_DIGITS
    
    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret for user.
        
        Returns:
            Base32-encoded secret string (16 bytes = 128 bits)
            
        Security Notes:
        - Uses cryptographically secure random generation
        - Base32 encoding for compatibility with authenticator apps
        - Store encrypted in database
        """
        # pyotp.random_base32() uses secrets module internally
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, secret: str, account_identifier: str) -> str:
        """
        Generate provisioning URI for QR code.
        
        Args:
            secret: TOTP secret
            account_identifier: User's email or username
            
        Returns:
            otpauth:// URI string
            
        Format: otpauth://totp/Issuer:account?secret=SECRET&issuer=Issuer
        """
        totp = pyotp.TOTP(
            secret, 
            interval=self.interval,
            digits=self.digits,
            issuer=self.issuer
        )
        
        return totp.provisioning_uri(
            name=account_identifier,
            issuer_name=self.issuer
        )
    
    def generate_qr_code(self, provisioning_uri: str) -> str:
        """
        Generate QR code image for TOTP setup.
        
        Args:
            provisioning_uri: otpauth:// URI
            
        Returns:
            Base64-encoded PNG image
            
        Usage:
            Display in <img> tag: <img src="data:image/png;base64,{qr_code}">
        """
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return img_str
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify TOTP token.
        
        Args:
            secret: User's TOTP secret
            token: 6-digit code from authenticator
            window: Time window tolerance (default 1 = ±30 seconds)
            
        Returns:
            True if token is valid
            
        Security Notes:
        - Window of 1 allows ±30 seconds for clock drift
        - Prevents token reuse within same time window (implement in caller)
        - Timing-safe comparison
        """
        if not token or len(token) != self.digits:
            return False
        
        totp = pyotp.TOTP(
            secret,
            interval=self.interval,
            digits=self.digits
        )
        
        # Verify with time window for clock drift tolerance
        # valid_window=1 checks current, previous, and next time windows
        return totp.verify(token, valid_window=window)
    
    def generate_backup_codes(self, count: int = None) -> List[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of codes to generate (default from config)
            
        Returns:
            List of backup codes (8-character alphanumeric)
            
        Security Notes:
        - Each code should be hashed before storage
        - Single-use codes (mark as used after verification)
        - Display to user only once during generation
        """
        if count is None:
            count = config.MFA_BACKUP_CODE_COUNT
        
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code (excluding ambiguous chars)
            code = token_generator.generate_alphanumeric_code(
                config.MFA_BACKUP_CODE_LENGTH
            )
            codes.append(code)
        
        return codes
    
    def hash_backup_code(self, code: str) -> str:
        """
        Hash backup code for secure storage.
        
        Args:
            code: Plain text backup code
            
        Returns:
            Hashed code (Argon2id)
            
        Security: Store hashed codes, never plaintext
        """
        # Use same password hashing for backup codes
        return password_hasher.hash_password(code)
    
    def verify_backup_code(self, code_hash: str, code: str) -> bool:
        """
        Verify backup code against hash.
        
        Args:
            code_hash: Stored hash
            code: User-provided code
            
        Returns:
            True if code matches
        """
        return password_hasher.verify_password(code_hash, code)
    
    def get_current_totp(self, secret: str) -> str:
        """
        Get current TOTP value (for testing/display).
        
        Args:
            secret: TOTP secret
            
        Returns:
            Current 6-digit code
            
        Note: Use only for testing or showing example to user
        """
        totp = pyotp.TOTP(secret, interval=self.interval, digits=self.digits)
        return totp.now()


class MFAEnforcer:
    """
    Enforces MFA requirements for sensitive operations.
    
    Dating Platform Specific:
    - Password reset requires MFA
    - Privacy settings changes require MFA
    - Payment operations require MFA
    - Location sharing activation requires MFA
    """
    
    @staticmethod
    def requires_mfa(operation: str) -> bool:
        """
        Check if operation requires MFA verification.
        
        Args:
            operation: Operation identifier
            
        Returns:
            True if MFA is required
        """
        mfa_required_operations = {
            'password_reset': config.MFA_REQUIRED_FOR_PASSWORD_RESET,
            'privacy_settings': config.MFA_REQUIRED_FOR_PRIVACY_SETTINGS,
            'payment': config.MFA_REQUIRED_FOR_PAYMENT,
            'location_sharing': True,  # Always require MFA for location
            'account_deletion': True,  # Critical operation
            'email_change': True,      # Account takeover risk
            'export_data': True,       # GDPR data export
        }
        
        return mfa_required_operations.get(operation, False)
    
    @staticmethod
    def verify_mfa_for_operation(
        user_has_mfa: bool,
        operation: str,
        mfa_token: Optional[str] = None,
        user_mfa_secret: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Verify MFA for sensitive operation.
        
        Args:
            user_has_mfa: Whether user has MFA enabled
            operation: Operation being performed
            mfa_token: TOTP token provided by user
            user_mfa_secret: User's TOTP secret (if MFA enabled)
            
        Returns:
            Tuple of (success, error_message)
        """
        # Check if operation requires MFA
        if not MFAEnforcer.requires_mfa(operation):
            return True, ""
        
        # If MFA required but user doesn't have it enabled
        if not user_has_mfa:
            return False, "MFA is required for this operation. Please enable MFA first."
        
        # If MFA token not provided
        if not mfa_token:
            return False, "MFA token is required for this operation"
        
        # Verify MFA token
        mfa_manager = MFAManager()
        if not mfa_manager.verify_totp(user_mfa_secret, mfa_token):
            return False, "Invalid MFA token"
        
        return True, ""


# Global MFA manager instance
mfa_manager = MFAManager()
mfa_enforcer = MFAEnforcer()


# Convenience functions
def setup_mfa_for_user(account_identifier: str) -> Tuple[str, str, str]:
    """
    Setup MFA for a user.
    
    Args:
        account_identifier: User's email or username
        
    Returns:
        Tuple of (secret, provisioning_uri, qr_code_base64)
        
    Usage:
        1. Generate secret and QR code
        2. Display QR code to user
        3. User scans with authenticator app
        4. User provides first TOTP token to confirm
        5. Store encrypted secret in database
    """
    secret = mfa_manager.generate_secret()
    provisioning_uri = mfa_manager.get_provisioning_uri(secret, account_identifier)
    qr_code = mfa_manager.generate_qr_code(provisioning_uri)
    
    return secret, provisioning_uri, qr_code


def verify_mfa_token(secret: str, token: str) -> bool:
    """
    Verify TOTP token.
    
    Args:
        secret: User's TOTP secret
        token: 6-digit code from authenticator
        
    Returns:
        True if valid
    """
    return mfa_manager.verify_totp(secret, token)


def generate_and_hash_backup_codes() -> Tuple[List[str], List[str]]:
    """
    Generate backup codes and return both plain and hashed versions.
    
    Returns:
        Tuple of (plain_codes, hashed_codes)
        
    Usage:
        1. Display plain_codes to user (one-time only)
        2. Store hashed_codes in database
        3. User stores plain codes securely
    """
    plain_codes = mfa_manager.generate_backup_codes()
    hashed_codes = [mfa_manager.hash_backup_code(code) for code in plain_codes]
    
    return plain_codes, hashed_codes