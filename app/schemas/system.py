"""
System and Product related schemas.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import re

from app.models.system import SystemStatus, Environment, Criticality, DataClassification


class SystemBase(BaseModel):
    """Base system fields."""
    
    system_id: str = Field(
        min_length=3,
        max_length=100,
        description="Unique system identifier (lowercase, alphanumeric with hyphens)"
    )
    display_name: str = Field(min_length=2, max_length=255, description="Human-readable name")
    description: Optional[str] = Field(default=None, max_length=2000)
    
    @field_validator("system_id")
    @classmethod
    def validate_system_id(cls, v: str) -> str:
        if not re.match(r'^[a-z][a-z0-9_-]{2,99}$', v.lower()):
            raise ValueError(
                "system_id must start with a letter, contain only lowercase letters, "
                "numbers, hyphens, and underscores"
            )
        return v.lower()
    
    @field_validator("display_name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        v = re.sub(r'[<>"\';\\]', '', v)
        return v.strip()


class SystemCreate(SystemBase):
    """Schema for creating a new system."""
    
    environment: Environment = Field(default=Environment.PRODUCTION)
    criticality: Criticality = Field(default=Criticality.MEDIUM)
    data_classifications: Optional[List[DataClassification]] = None
    
    # Ownership
    owner_team_id: Optional[int] = None
    owner_user_id: Optional[int] = None
    backup_owner_id: Optional[int] = None
    
    # Business context
    business_process_ids: Optional[List[int]] = Field(
        default=None,
        description="Business process IDs this system supports"
    )
    product_ids: Optional[List[int]] = Field(
        default=None,
        description="Product IDs this system belongs to"
    )
    
    # Compliance
    framework_ids: Optional[List[int]] = Field(
        default=None,
        description="Framework IDs applicable to this system"
    )
    
    # Integration
    ingest_source: Optional[str] = Field(default=None, max_length=500)
    sbom_url: Optional[str] = Field(default=None, max_length=500)
    cmdb_link: Optional[str] = Field(default=None, max_length=500)


class SystemUpdate(BaseModel):
    """Schema for updating a system."""
    
    display_name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[SystemStatus] = None
    environment: Optional[Environment] = None
    criticality: Optional[Criticality] = None
    data_classifications: Optional[List[DataClassification]] = None
    
    # Ownership
    owner_team_id: Optional[int] = None
    owner_user_id: Optional[int] = None
    backup_owner_id: Optional[int] = None
    
    # Business context
    business_process_ids: Optional[List[int]] = None
    product_ids: Optional[List[int]] = None
    framework_ids: Optional[List[int]] = None
    
    # Integration
    ingest_source: Optional[str] = Field(default=None, max_length=500)
    sbom_url: Optional[str] = Field(default=None, max_length=500)
    cmdb_link: Optional[str] = Field(default=None, max_length=500)


class SystemDeprecateRequest(BaseModel):
    """Request to deprecate a system."""
    
    reason: str = Field(min_length=10, max_length=1000, description="Reason for deprecation")
    replacement_system_id: Optional[str] = Field(
        default=None,
        description="ID of system replacing this one"
    )
    scheduled_archive_date: Optional[datetime] = Field(
        default=None,
        description="When to auto-archive this system"
    )
    notify_owner: bool = Field(default=True, description="Notify system owner")


class SystemResponse(BaseModel):
    """Schema for system response."""
    
    id: int
    system_id: str
    display_name: str
    description: Optional[str] = None
    status: SystemStatus
    environment: Environment
    criticality: Criticality
    data_classifications: List[DataClassification] = Field(default_factory=list)
    
    # Ownership
    owner_team: Optional[str] = Field(default=None, description="Owner team name")
    owner_user: Optional[str] = Field(default=None, description="Owner user email")
    
    # Relationships (counts for list view, full objects for detail view)
    business_process_count: int = 0
    product_count: int = 0
    framework_count: int = 0
    
    # Compliance status (cached/computed)
    compliance_status: Optional[str] = Field(
        default=None,
        description="Current compliance status (healthy, failing, unknown)"
    )
    failure_count: int = Field(default=0, description="Number of active failures")
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
    deprecated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class SystemDetailResponse(SystemResponse):
    """Extended system response with full relationships."""
    
    # Full relationship data
    business_processes: List[str] = Field(default_factory=list, description="Process names")
    products: List[str] = Field(default_factory=list, description="Product names")
    frameworks: List[str] = Field(default_factory=list, description="Framework IDs")
    
    # Deprecation info
    deprecation_reason: Optional[str] = None
    replacement_system: Optional[str] = None
    scheduled_archive_date: Optional[datetime] = None
    
    # Integration
    ingest_source: Optional[str] = None
    sbom_url: Optional[str] = None
    cmdb_link: Optional[str] = None


class SystemListResponse(BaseModel):
    """Paginated list of systems."""
    
    items: List[SystemResponse]
    total: int
    page: int
    per_page: int
    pages: int


# Product schemas

class ProductCreate(BaseModel):
    """Schema for creating a product."""
    
    product_id: str = Field(min_length=3, max_length=100)
    display_name: str = Field(min_length=2, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    owner_team_id: Optional[int] = None
    product_manager_id: Optional[int] = None
    system_ids: Optional[List[int]] = None
    
    @field_validator("product_id")
    @classmethod
    def validate_product_id(cls, v: str) -> str:
        if not re.match(r'^[a-z][a-z0-9_-]{2,99}$', v.lower()):
            raise ValueError(
                "product_id must start with a letter, contain only lowercase letters, "
                "numbers, hyphens, and underscores"
            )
        return v.lower()


class ProductResponse(BaseModel):
    """Schema for product response."""
    
    id: int
    product_id: str
    display_name: str
    description: Optional[str] = None
    is_active: bool
    owner_team: Optional[str] = None
    product_manager: Optional[str] = None
    system_count: int = 0
    certifications: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class BusinessProcessResponse(BaseModel):
    """Schema for business process response."""
    
    id: int
    name: str
    description: Optional[str] = None
    criticality: Criticality
    owner_team: Optional[str] = None
    system_count: int = 0
    created_at: datetime
    
    class Config:
        from_attributes = True

