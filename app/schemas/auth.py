"""
Authentication-related schemas.
"""

from typing import Optional
from pydantic import BaseModel, Field, EmailStr, field_validator
import re


class LoginRequest(BaseModel):
    """Login request with email and password."""
    
    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=1, max_length=128, description="User password")
    
    @field_validator("email")
    @classmethod
    def lowercase_email(cls, v: str) -> str:
        return v.lower().strip()


class LoginResponse(BaseModel):
    """Login response with tokens."""
    
    access_token: str = Field(description="JWT access token")
    refresh_token: str = Field(description="JWT refresh token for token renewal")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Access token expiration in seconds")
    
    # User info
    user_id: int = Field(description="User's database ID")
    email: str = Field(description="User's email")
    role: str = Field(description="User's role")
    full_name: str = Field(description="User's full name")


class TokenRefreshRequest(BaseModel):
    """Request to refresh access token."""
    
    refresh_token: str = Field(description="Current refresh token")


class TokenRefreshResponse(BaseModel):
    """Response with new access token."""
    
    access_token: str = Field(description="New JWT access token")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(description="Access token expiration in seconds")


class PasswordChangeRequest(BaseModel):
    """Request to change password."""
    
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)
    
    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Ensure password meets complexity requirements."""
        errors = []
        
        if len(v) < 12:
            errors.append("at least 12 characters")
        if not re.search(r'[A-Z]', v):
            errors.append("one uppercase letter")
        if not re.search(r'[a-z]', v):
            errors.append("one lowercase letter")
        if not re.search(r'\d', v):
            errors.append("one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            errors.append("one special character")
        
        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")
        
        return v


class APITokenResponse(BaseModel):
    """Response when generating new API token."""
    
    token: str = Field(description="The API token (only shown once!)")
    expires_at: str = Field(description="Token expiration datetime (ISO format)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "pact_aBc123XyZ...",
                "expires_at": "2025-04-05T12:00:00Z"
            }
        }


class APITokenRevokeRequest(BaseModel):
    """Request to revoke API token."""
    
    confirm: bool = Field(
        default=False,
        description="Must be true to confirm revocation"
    )

