"""
Common schemas used across the API.
"""

from typing import Optional, Generic, TypeVar, List, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
import re

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Pagination parameters for list endpoints."""
    
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    per_page: int = Field(default=20, ge=1, le=100, description="Items per page (max 100)")
    
    @property
    def offset(self) -> int:
        """Calculate SQL offset from page number."""
        return (self.page - 1) * self.per_page
    
    @property
    def limit(self) -> int:
        """SQL limit is same as per_page."""
        return self.per_page


class FilterParams(BaseModel):
    """
    Universal filter parameters.
    
    Supports filtering by common dimensions across all list endpoints.
    """
    
    # Entity filters
    systems: Optional[List[str]] = Field(default=None, description="Filter by system IDs")
    teams: Optional[List[str]] = Field(default=None, description="Filter by team names")
    products: Optional[List[str]] = Field(default=None, description="Filter by product IDs")
    
    # Compliance filters
    frameworks: Optional[List[str]] = Field(default=None, description="Filter by framework IDs")
    controls: Optional[List[str]] = Field(default=None, description="Filter by control IDs")
    status: Optional[List[str]] = Field(default=None, description="Filter by status (PASS, FAIL, etc.)")
    severity: Optional[List[str]] = Field(default=None, description="Filter by severity")
    
    # Time filters
    from_date: Optional[datetime] = Field(default=None, description="Start date for time range")
    to_date: Optional[datetime] = Field(default=None, description="End date for time range")
    
    # Search
    search: Optional[str] = Field(default=None, max_length=200, description="Search query")
    
    @field_validator("search")
    @classmethod
    def sanitize_search(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize search input to prevent injection."""
        if v is None:
            return None
        # Remove potentially dangerous characters
        v = re.sub(r'[<>"\';\\]', '', v)
        return v.strip()


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""
    
    items: List[T]
    total: int = Field(description="Total number of items matching filters")
    page: int = Field(description="Current page number")
    per_page: int = Field(description="Items per page")
    pages: int = Field(description="Total number of pages")
    
    @classmethod
    def create(
        cls,
        items: List[T],
        total: int,
        page: int,
        per_page: int,
    ) -> "PaginatedResponse[T]":
        """Factory method to create paginated response."""
        pages = (total + per_page - 1) // per_page if per_page > 0 else 0
        return cls(
            items=items,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
        )


class SuccessResponse(BaseModel):
    """Generic success response."""
    
    success: bool = True
    message: str = "Operation completed successfully"
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    """Error response format."""
    
    success: bool = False
    error: str = Field(description="Error type/code")
    message: str = Field(description="Human-readable error message")
    details: Optional[Any] = Field(default=None, description="Additional error details")


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str = "healthy"
    version: str
    database: str = "connected"
    timestamp: datetime


# Validators for common fields
def validate_identifier(v: str) -> str:
    """
    Validate an identifier (system_id, product_id, etc.).
    Must be alphanumeric with hyphens/underscores, 3-100 chars.
    """
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,99}$', v):
        raise ValueError(
            "Identifier must start with a letter, contain only letters, "
            "numbers, hyphens, and underscores, and be 3-100 characters"
        )
    return v.lower()


def validate_email(v: str) -> str:
    """Validate email format."""
    # Basic email validation (more thorough validation done by pydantic EmailStr)
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
        raise ValueError("Invalid email format")
    return v.lower()

