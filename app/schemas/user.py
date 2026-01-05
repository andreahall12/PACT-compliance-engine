"""
User-related schemas.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, field_validator
import re

from app.models.user import UserRole


class UserBase(BaseModel):
    """Base user fields."""
    
    email: EmailStr = Field(description="User email address")
    full_name: str = Field(min_length=2, max_length=255, description="User's full name")
    role: UserRole = Field(description="User's role for access control")
    
    @field_validator("email")
    @classmethod
    def lowercase_email(cls, v: str) -> str:
        return v.lower().strip()
    
    @field_validator("full_name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        # Remove potentially dangerous characters
        v = re.sub(r'[<>"\';\\]', '', v)
        return v.strip()


class UserCreate(UserBase):
    """Schema for creating a new user."""
    
    password: Optional[str] = Field(
        default=None,
        min_length=12,
        max_length=128,
        description="Initial password. If not provided, a temporary password will be generated."
    )
    team_ids: Optional[List[int]] = Field(
        default=None,
        description="Team IDs to assign user to"
    )
    send_welcome_email: bool = Field(
        default=True,
        description="Whether to send welcome email with credentials"
    )
    
    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        
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


class UserUpdate(BaseModel):
    """Schema for updating a user."""
    
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    team_ids: Optional[List[int]] = None
    
    @field_validator("email")
    @classmethod
    def lowercase_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return v.lower().strip()


class UserResponse(BaseModel):
    """Schema for user response (no sensitive data)."""
    
    id: int
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_verified: bool
    teams: List[str] = Field(default_factory=list, description="Team names")
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Paginated list of users."""
    
    items: List[UserResponse]
    total: int
    page: int
    per_page: int
    pages: int


class UserProfileResponse(BaseModel):
    """Extended user profile for self-view."""
    
    id: int
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_verified: bool
    teams: List[str] = Field(default_factory=list)
    created_at: datetime
    last_login: Optional[datetime] = None
    
    # Additional profile fields
    has_api_token: bool = Field(description="Whether user has an active API token")
    api_token_expires: Optional[datetime] = None
    notification_preferences: Optional[dict] = None
    
    class Config:
        from_attributes = True


class UserNotificationPrefs(BaseModel):
    """User notification preferences."""
    
    email_enabled: bool = True
    email_frequency: str = Field(
        default="immediate",
        pattern="^(immediate|daily|weekly)$"
    )
    
    slack_enabled: bool = False
    slack_channel: Optional[str] = None
    
    # What to notify about
    notify_on_failure: bool = True
    notify_on_drift: bool = True
    notify_on_exception_expiry: bool = True
    notify_on_document_expiry: bool = True


class TeamResponse(BaseModel):
    """Team information."""
    
    id: int
    name: str
    description: Optional[str] = None
    member_count: int = 0
    created_at: datetime
    
    class Config:
        from_attributes = True

