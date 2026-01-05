"""
Authentication endpoints.

Provides:
- Login (email/password → JWT tokens)
- Token refresh
- Logout
- Password change
- API token management
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.user import User
from app.models.audit import AuditLog, AuditAction
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    verify_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.auth.password import verify_password, needs_rehash, hash_password
from app.auth.dependencies import get_current_user, get_client_ip, get_user_agent
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
    PasswordChangeRequest,
    APITokenResponse,
)

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and return JWT tokens.
    
    Sets HttpOnly cookie for refresh token (more secure than localStorage).
    Returns access token in response body.
    """
    # Find user
    result = await db.execute(
        select(User).where(User.email == login_data.email.lower())
    )
    user = result.scalar_one_or_none()
    
    # Check if user exists and password matches
    if not user or not user.verify_password(login_data.password):
        # Record failed attempt if user exists
        if user:
            user.record_failed_login()
            await db.commit()
            
            # Audit log
            audit = AuditLog.create(
                action=AuditAction.LOGIN_FAILURE,
                user_id=user.id,
                user_email=user.email,
                details={"reason": "invalid_password"},
                success=False,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
            )
            db.add(audit)
            await db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Check if account is locked
    if user.is_locked():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is locked. Try again later.",
        )
    
    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )
    
    # Check if password needs rehash (security parameter upgrade)
    if needs_rehash(user.password_hash):
        user.set_password(login_data.password)
    
    # Record successful login
    user.record_successful_login()
    
    # Generate tokens
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
    )
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.LOGIN_SUCCESS,
        user_id=user.id,
        user_email=user.email,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    await db.commit()
    
    # Set refresh token as HttpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,  # Requires HTTPS in production
        samesite="lax",
        max_age=7 * 24 * 60 * 60,  # 7 days
    )
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        email=user.email,
        role=user.role.value,
        full_name=user.full_name,
    )


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(
    request: Request,
    token_data: TokenRefreshRequest = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token.
    
    Accepts refresh token from:
    1. Request body (preferred for SPAs)
    2. HttpOnly cookie (for web apps)
    """
    # Get refresh token from body or cookie
    refresh_token = None
    if token_data and token_data.refresh_token:
        refresh_token = token_data.refresh_token
    else:
        refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
        )
    
    # Verify token
    try:
        payload = verify_token(refresh_token, expected_type="refresh")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {str(e)}",
        )
    
    # Verify user still exists and is active
    result = await db.execute(
        select(User).where(User.id == int(payload.sub))
    )
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    # Generate new access token
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
    )
    
    return TokenRefreshResponse(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout user by clearing cookies.
    
    Note: JWTs cannot be truly invalidated. For full logout:
    - Clear cookies
    - Client should discard tokens
    - Consider token blacklist for high-security apps
    """
    # Clear refresh token cookie
    response.delete_cookie("refresh_token")
    response.delete_cookie("access_token")
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.LOGOUT,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    await db.commit()
    
    return {"message": "Successfully logged out"}


@router.post("/change-password")
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the current user's password."""
    
    # Verify current password
    if not current_user.verify_password(password_data.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    
    # Set new password
    current_user.set_password(password_data.new_password)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.PASSWORD_CHANGE,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    await db.commit()
    
    return {"message": "Password changed successfully"}


@router.post("/api-token", response_model=APITokenResponse)
async def generate_api_token(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a new API token for the current user.
    
    ⚠️ The token is only shown once! Store it securely.
    
    This token can be used instead of JWT for API access.
    Useful for CI/CD pipelines and scripts.
    """
    # Generate new token
    raw_token = current_user.generate_api_token()
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.API_TOKEN_GENERATED,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    await db.commit()
    
    return APITokenResponse(
        token=f"pact_{raw_token}",
        expires_at=current_user.api_token_expires.isoformat(),
    )


@router.delete("/api-token")
async def revoke_api_token(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the current user's API token."""
    
    current_user.api_token_hash = None
    current_user.api_token_expires = None
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.API_TOKEN_REVOKED,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    await db.commit()
    
    return {"message": "API token revoked"}


@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
):
    """Get current user's profile information."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "has_api_token": current_user.api_token_hash is not None,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat(),
    }

