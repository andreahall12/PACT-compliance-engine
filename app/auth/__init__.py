"""
Authentication and Authorization module.

Provides:
- JWT token generation and validation
- Password hashing (Argon2id)
- Role-based access control
- Audit logging for auth events
"""

from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    verify_token,
    get_token_payload,
    TokenPayload,
)
from app.auth.dependencies import (
    get_current_user,
    get_current_active_user,
    require_role,
    require_permission,
    get_optional_user,
)
from app.auth.password import (
    hash_password,
    verify_password,
)

__all__ = [
    # JWT
    "create_access_token",
    "create_refresh_token", 
    "verify_token",
    "get_token_payload",
    "TokenPayload",
    # Dependencies
    "get_current_user",
    "get_current_active_user",
    "require_role",
    "require_permission",
    "get_optional_user",
    # Password
    "hash_password",
    "verify_password",
]

