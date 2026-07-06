import hmac

from fastapi import Header, HTTPException

from .config import settings


def require_token(authorization: str = Header(default="")) -> None:
    expected = f"Bearer {settings.edr_api_token}"
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid or missing token")
