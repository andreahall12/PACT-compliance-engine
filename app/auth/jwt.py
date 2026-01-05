"""
JWT Token handling with security best practices.

Security measures:
- Short-lived access tokens (15 min default)
- Longer-lived refresh tokens (7 days)
- Secure secret key from environment
- Token type validation
- Issuer and audience validation
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from pydantic import BaseModel
from jose import jwt, JWTError, ExpiredSignatureError

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    # Generate a random key for development (NOT for production!)
    JWT_SECRET_KEY = secrets.token_urlsafe(32)
    print("⚠️  WARNING: Using auto-generated JWT_SECRET_KEY. Set JWT_SECRET_KEY env var in production!")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", "pact-api")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "pact-client")


class TokenPayload(BaseModel):
    """JWT token payload structure."""
    sub: str                          # User ID (subject)
    email: str                        # User email
    role: str                         # User role
    type: str                         # "access" or "refresh"
    iat: datetime                     # Issued at
    exp: datetime                     # Expiration
    iss: str = TOKEN_ISSUER           # Issuer
    aud: str = TOKEN_AUDIENCE         # Audience
    jti: Optional[str] = None         # JWT ID (for token revocation)


def create_access_token(
    user_id: int,
    email: str,
    role: str,
    additional_claims: Optional[dict[str, Any]] = None
) -> str:
    """
    Create a short-lived access token.
    
    Args:
        user_id: The user's database ID
        email: User's email address
        role: User's role for RBAC
        additional_claims: Optional extra claims to include
    
    Returns:
        Encoded JWT string
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": expire,
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "jti": secrets.token_urlsafe(16),  # Unique token ID
    }
    
    if additional_claims:
        payload.update(additional_claims)
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(
    user_id: int,
    email: str,
    role: str,
) -> str:
    """
    Create a longer-lived refresh token.
    
    Refresh tokens should be:
    - Stored securely (HttpOnly cookie or secure storage)
    - Rotated on use
    - Revocable via database
    
    Args:
        user_id: The user's database ID
        email: User's email address
        role: User's role
    
    Returns:
        Encoded JWT string
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "type": "refresh",
        "iat": now,
        "exp": expire,
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "jti": secrets.token_urlsafe(16),
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> TokenPayload:
    """
    Verify and decode a JWT token.
    
    Args:
        token: The JWT string to verify
        expected_type: Expected token type ("access" or "refresh")
    
    Returns:
        TokenPayload with decoded claims
    
    Raises:
        JWTError: If token is invalid, expired, or wrong type
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=TOKEN_AUDIENCE,
            issuer=TOKEN_ISSUER,
        )
        
        # Validate token type
        if payload.get("type") != expected_type:
            raise JWTError(f"Invalid token type. Expected {expected_type}, got {payload.get('type')}")
        
        return TokenPayload(
            sub=payload["sub"],
            email=payload["email"],
            role=payload["role"],
            type=payload["type"],
            iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            iss=payload.get("iss", TOKEN_ISSUER),
            aud=payload.get("aud", TOKEN_AUDIENCE),
            jti=payload.get("jti"),
        )
        
    except ExpiredSignatureError:
        raise JWTError("Token has expired")
    except JWTError:
        raise


def get_token_payload(token: str) -> Optional[TokenPayload]:
    """
    Decode token without verification (for debugging/logging).
    Returns None if token is malformed.
    
    ⚠️ Do NOT use this for authentication - use verify_token instead.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": False, "verify_aud": False, "verify_iss": False}
        )
        return TokenPayload(
            sub=payload["sub"],
            email=payload["email"],
            role=payload["role"],
            type=payload["type"],
            iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            iss=payload.get("iss", ""),
            aud=payload.get("aud", ""),
            jti=payload.get("jti"),
        )
    except Exception:
        return None

