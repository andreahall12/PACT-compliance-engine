"""
FastAPI dependencies for authentication and authorization.

Provides:
- get_current_user: Extract and validate user from JWT
- require_role: Decorator to require specific roles
- require_permission: Decorator to require specific permissions
"""

from typing import Optional, Callable, Any
from functools import wraps
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError

from app.core.database import get_db
from app.auth.jwt import verify_token, TokenPayload
from app.models.user import User, UserRole, ROLE_PERMISSIONS

# HTTP Bearer token extractor
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate the current user from JWT token.
    
    Looks for token in:
    1. Authorization: Bearer <token> header
    2. Cookie: access_token
    
    Raises:
        HTTPException 401: If token is missing or invalid
        HTTPException 401: If user not found or inactive
    """
    token = None
    
    # Try Authorization header first
    if credentials:
        token = credentials.credentials
    else:
        # Try cookie
        token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        payload = verify_token(token, expected_type="access")
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Fetch user from database
    result = await db.execute(
        select(User).where(User.id == int(payload.sub))
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )
    
    if user.is_locked():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is locked",
        )
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get current user, ensuring they are active.
    This is an alias for get_current_user with explicit active check.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return current_user


async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Try to get current user, but return None if not authenticated.
    Useful for endpoints that work differently for authenticated vs anonymous users.
    """
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


def require_role(*allowed_roles: UserRole):
    """
    Dependency to require specific role(s).
    
    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(
            user: User = Depends(require_role(UserRole.ADMIN))
        ):
            ...
    
    Args:
        allowed_roles: One or more UserRole values that are permitted
    
    Returns:
        Dependency function that validates role
    """
    async def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role.value}' not authorized for this action",
            )
        return current_user
    
    return role_checker


def require_permission(permission: str):
    """
    Dependency to require specific permission.
    
    Permissions are mapped from roles in ROLE_PERMISSIONS.
    
    Usage:
        @router.post("/users")
        async def create_user(
            user: User = Depends(require_permission("users.create"))
        ):
            ...
    
    Args:
        permission: Permission string (e.g., "users.create", "systems.read")
    
    Returns:
        Dependency function that validates permission
    """
    async def permission_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_permissions = ROLE_PERMISSIONS.get(current_user.role, set())
        
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return current_user
    
    return permission_checker


class RoleChecker:
    """
    Class-based dependency for role checking.
    Allows more complex role validation logic.
    
    Usage:
        role_check = RoleChecker([UserRole.ADMIN, UserRole.COMPLIANCE_OFFICER])
        
        @router.get("/")
        async def endpoint(user: User = Depends(role_check)):
            ...
    """
    
    def __init__(self, allowed_roles: list[UserRole]):
        self.allowed_roles = allowed_roles
    
    async def __call__(
        self,
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role.value}' not authorized",
            )
        return current_user


class PermissionChecker:
    """
    Class-based dependency for permission checking.
    Supports multiple permissions (any or all).
    
    Usage:
        # Require ANY of these permissions
        can_view = PermissionChecker(["systems.read", "systems.update"], require_all=False)
        
        # Require ALL of these permissions
        can_manage = PermissionChecker(["users.create", "users.update"], require_all=True)
    """
    
    def __init__(self, permissions: list[str], require_all: bool = False):
        self.permissions = permissions
        self.require_all = require_all
    
    async def __call__(
        self,
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_permissions = ROLE_PERMISSIONS.get(current_user.role, set())
        
        if self.require_all:
            # User must have ALL permissions
            if not all(p in user_permissions for p in self.permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires all permissions: {self.permissions}",
                )
        else:
            # User must have ANY permission
            if not any(p in user_permissions for p in self.permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires at least one permission from: {self.permissions}",
                )
        
        return current_user


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address from request.
    Handles X-Forwarded-For header for proxied requests.
    """
    # Check for proxy headers
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP (original client)
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct connection
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request headers."""
    return request.headers.get("User-Agent", "unknown")[:500]  # Limit length

