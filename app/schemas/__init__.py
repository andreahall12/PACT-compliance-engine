"""
Pydantic schemas for API request/response validation.

These schemas provide:
- Input validation with security constraints
- Output serialization
- OpenAPI documentation generation
"""

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
    PasswordChangeRequest,
)
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
)
from app.schemas.system import (
    SystemCreate,
    SystemUpdate,
    SystemResponse,
    SystemListResponse,
)
from app.schemas.common import (
    PaginationParams,
    FilterParams,
    SuccessResponse,
    ErrorResponse,
)

__all__ = [
    # Auth
    "LoginRequest",
    "LoginResponse",
    "TokenRefreshRequest",
    "TokenRefreshResponse",
    "PasswordChangeRequest",
    # User
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserListResponse",
    # System
    "SystemCreate",
    "SystemUpdate",
    "SystemResponse",
    "SystemListResponse",
    # Common
    "PaginationParams",
    "FilterParams",
    "SuccessResponse",
    "ErrorResponse",
]

