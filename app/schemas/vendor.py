"""
Vendor-related Pydantic schemas.
"""

from datetime import datetime, date
from typing import Optional, List, Dict

from pydantic import BaseModel, Field

from app.models.vendor import VendorRisk, VendorCategory


class VendorCreate(BaseModel):
    """Create a new vendor."""
    vendor_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: VendorCategory = VendorCategory.SAAS
    risk_level: VendorRisk = VendorRisk.MEDIUM
    website: Optional[str] = None
    primary_contact_name: Optional[str] = None
    primary_contact_email: Optional[str] = None
    security_contact_email: Optional[str] = None
    contract_start_date: Optional[date] = None
    contract_end_date: Optional[date] = None
    data_access: Optional[List[str]] = Field(None, description="Types of data shared with vendor")


class VendorUpdate(BaseModel):
    """Update vendor details."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[VendorCategory] = None
    risk_level: Optional[VendorRisk] = None
    website: Optional[str] = None
    primary_contact_name: Optional[str] = None
    primary_contact_email: Optional[str] = None
    security_contact_email: Optional[str] = None
    contract_start_date: Optional[date] = None
    contract_end_date: Optional[date] = None
    is_active: Optional[bool] = None
    has_soc2: Optional[bool] = None
    soc2_type: Optional[str] = None
    soc2_report_date: Optional[date] = None
    soc2_expiration_date: Optional[date] = None


class VendorResponse(BaseModel):
    """Vendor response model."""
    id: int
    vendor_id: str
    name: str
    description: Optional[str]
    category: str
    risk_level: str
    website: Optional[str]
    is_active: bool
    primary_contact_name: Optional[str]
    primary_contact_email: Optional[str]
    security_contact_email: Optional[str]
    contract_start_date: Optional[date]
    contract_end_date: Optional[date]
    has_soc2: bool
    soc2_status: Optional[str]
    last_risk_assessment: Optional[date]
    next_risk_assessment: Optional[date]
    needs_review: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class VendorRiskSummary(BaseModel):
    """Summary of vendor risk across the organization."""
    total_vendors: int
    active_vendors: int
    by_risk_level: Dict[str, int]
    upcoming_assessments: int
    expired_soc2: int
    needs_review: int


def vendor_to_response(v) -> VendorResponse:
    """
    Convert Vendor model to VendorResponse.
    
    Args:
        v: Vendor model instance
        
    Returns:
        VendorResponse schema instance
    """
    return VendorResponse(
        id=v.id,
        vendor_id=v.vendor_id,
        name=v.name,
        description=v.description,
        category=v.category.value,
        risk_level=v.risk_level.value,
        website=v.website,
        is_active=v.is_active,
        primary_contact_name=v.primary_contact_name,
        primary_contact_email=v.primary_contact_email,
        security_contact_email=v.security_contact_email,
        contract_start_date=v.contract_start_date,
        contract_end_date=v.contract_end_date,
        has_soc2=v.has_soc2,
        soc2_status=v.get_soc2_status().value,
        last_risk_assessment=v.last_risk_assessment,
        next_risk_assessment=v.next_risk_assessment,
        needs_review=v.needs_review(),
        created_at=v.created_at,
    )

