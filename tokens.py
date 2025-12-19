import jwt
import datetime
from config import settings

class TokenService:
    @staticmethod
    def create_access_token(user_id: str, scope: dict) -> str:
        """
        Short-lived JWT for API access.
        Scope includes specific dating-app permissions (e.g., can_message).
        """
        payload = {
            "sub": user_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_ACCESS_LIFETIME),
            "iat": datetime.datetime.utcnow(),
            "scope": scope,
            "iss": f"dating-platform-{settings.STUDENT_ID}"
        }
        return jwt.encode(payload, settings.JWT_SIGNING_KEY, algorithm="HS256")

    @staticmethod
    def create_refresh_token() -> str:
        """
        Opaque high-entropy string for refresh token.
        NOT a JWT. Stored encrypted in DB.
        """
        return secrets.token_urlsafe(64)