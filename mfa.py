import pyotp
from crypto import crypto_manager
from utils import Validator

class MFAService:
    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(user_email: str, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=f"DatingApp-{settings.STUDENT_ID}"
        )

    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1) # Allow 30s drift

    @staticmethod
    def generate_backup_codes(count=10) -> list[str]:
        return [Validator.generate_token(4) for _ in range(count)]