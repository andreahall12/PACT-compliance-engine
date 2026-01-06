"""
Policy-related Pydantic schemas.
"""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field

from app.models.policy import PolicyType


class PolicyCreate(BaseModel):
    """Create a new policy."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    policy_type: PolicyType = PolicyType.SHACL
    framework: Optional[str] = Field(None, description="Associated framework (e.g., NIST, PCI-DSS)")
    version: str = Field("1.0.0", description="Policy version")
    is_active: bool = Field(True, description="Whether policy is active")


class PolicyUpdate(BaseModel):
    """Update policy metadata."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    framework: Optional[str] = None
    version: Optional[str] = None
    is_active: Optional[bool] = None


class PolicyResponse(BaseModel):
    """Policy response model."""
    id: int
    name: str
    description: Optional[str]
    policy_type: str
    framework: Optional[str]
    version: str
    is_active: bool
    file_path: Optional[str]
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PolicyValidationResult(BaseModel):
    """Result of policy validation."""
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    shape_count: int = 0
    target_classes: List[str] = []


def policy_to_response(p, created_by_email: Optional[str] = None) -> PolicyResponse:
    """
    Convert Policy model to PolicyResponse.
    
    Args:
        p: Policy model instance
        created_by_email: Optional email of the user who created the policy
        
    Returns:
        PolicyResponse schema instance
    """
    return PolicyResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        policy_type=p.policy_type.value,
        framework=p.framework,
        version=p.version,
        is_active=p.is_active,
        file_path=p.file_path,
        created_by=created_by_email,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )

