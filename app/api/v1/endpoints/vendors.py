"""
Vendor Risk Management endpoints.

Manages third-party vendor compliance and risk assessment.
"""

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.user import User
from app.models.vendor import Vendor, VendorRisk, VendorCategory
from app.auth.dependencies import require_permission
from app.schemas.common import PaginatedResponse
from app.schemas.vendor import (
    VendorCreate,
    VendorUpdate,
    VendorResponse,
    VendorRiskSummary,
    vendor_to_response,
)

router = APIRouter()


@router.get("", response_model=PaginatedResponse[VendorResponse])
async def list_vendors(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    risk_level: Optional[VendorRisk] = None,
    category: Optional[VendorCategory] = None,
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = None,
    current_user: User = Depends(require_permission("vendors.read")),
    db: AsyncSession = Depends(get_db),
):
    """List vendors with pagination and filtering."""
    query = select(Vendor).where(Vendor.deleted_at.is_(None))
    count_query = select(func.count(Vendor.id)).where(Vendor.deleted_at.is_(None))
    
    if risk_level:
        query = query.where(Vendor.risk_level == risk_level)
        count_query = count_query.where(Vendor.risk_level == risk_level)
    
    if category:
        query = query.where(Vendor.category == category)
        count_query = count_query.where(Vendor.category == category)
    
    if is_active is not None:
        query = query.where(Vendor.is_active == is_active)
        count_query = count_query.where(Vendor.is_active == is_active)
    
    if search:
        search_filter = f"%{search.lower()}%"
        query = query.where(Vendor.name.ilike(search_filter))
        count_query = count_query.where(Vendor.name.ilike(search_filter))
    
    result = await db.execute(count_query)
    total = result.scalar() or 0
    
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Vendor.name)
    
    result = await db.execute(query)
    vendors = result.scalars().all()
    
    return PaginatedResponse.create(
        items=[vendor_to_response(v) for v in vendors],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("", response_model=VendorResponse, status_code=status.HTTP_201_CREATED)
async def create_vendor(
    vendor_data: VendorCreate,
    current_user: User = Depends(require_permission("vendors.create")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new vendor record."""
    # Check for duplicate vendor_id
    result = await db.execute(
        select(Vendor).where(Vendor.vendor_id == vendor_data.vendor_id)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vendor with ID '{vendor_data.vendor_id}' already exists",
        )
    
    vendor = Vendor(
        vendor_id=vendor_data.vendor_id,
        name=vendor_data.name,
        description=vendor_data.description,
        category=vendor_data.category,
        risk_level=vendor_data.risk_level,
        website=vendor_data.website,
        is_active=True,
        primary_contact_name=vendor_data.primary_contact_name,
        primary_contact_email=vendor_data.primary_contact_email,
        security_contact_email=vendor_data.security_contact_email,
        contract_start_date=vendor_data.contract_start_date,
        contract_end_date=vendor_data.contract_end_date,
        owner_id=current_user.id,
    )
    
    if vendor_data.data_access:
        vendor.data_access = json.dumps(vendor_data.data_access)
    
    db.add(vendor)
    await db.commit()
    await db.refresh(vendor)
    
    return vendor_to_response(vendor)


@router.get("/risk-summary", response_model=VendorRiskSummary)
async def get_vendor_risk_summary(
    current_user: User = Depends(require_permission("vendors.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a summary of vendor risk across the organization."""
    # Count total
    result = await db.execute(
        select(func.count(Vendor.id)).where(Vendor.deleted_at.is_(None))
    )
    total = result.scalar() or 0
    
    # Count active
    result = await db.execute(
        select(func.count(Vendor.id)).where(
            Vendor.deleted_at.is_(None),
            Vendor.is_active == True
        )
    )
    active = result.scalar() or 0
    
    # Count by risk level
    by_risk = {}
    for level in VendorRisk:
        result = await db.execute(
            select(func.count(Vendor.id)).where(
                Vendor.deleted_at.is_(None),
                Vendor.risk_level == level
            )
        )
        by_risk[level.value] = result.scalar() or 0
    
    # Count vendors needing assessment (next_risk_assessment <= today)
    today = date.today()
    result = await db.execute(
        select(func.count(Vendor.id)).where(
            Vendor.deleted_at.is_(None),
            Vendor.next_risk_assessment <= today
        )
    )
    upcoming = result.scalar() or 0
    
    # Count expired SOC 2
    result = await db.execute(
        select(func.count(Vendor.id)).where(
            Vendor.deleted_at.is_(None),
            Vendor.has_soc2 == True,
            Vendor.soc2_expiration_date < today
        )
    )
    expired_soc2 = result.scalar() or 0
    
    return VendorRiskSummary(
        total_vendors=total,
        active_vendors=active,
        by_risk_level=by_risk,
        upcoming_assessments=upcoming,
        expired_soc2=expired_soc2,
        needs_review=upcoming,
    )


@router.get("/{vendor_id}", response_model=VendorResponse)
async def get_vendor(
    vendor_id: str,
    current_user: User = Depends(require_permission("vendors.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific vendor by ID."""
    # Support both numeric DB ID and string vendor_id
    if vendor_id.isdigit():
        query = select(Vendor).where(
            Vendor.id == int(vendor_id),
            Vendor.deleted_at.is_(None)
        )
    else:
        query = select(Vendor).where(
            Vendor.vendor_id == vendor_id,
            Vendor.deleted_at.is_(None)
        )
    
    result = await db.execute(query)
    vendor = result.scalar_one_or_none()
    
    if not vendor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vendor not found",
        )
    
    return vendor_to_response(vendor)


@router.patch("/{vendor_id}", response_model=VendorResponse)
async def update_vendor(
    vendor_id: str,
    vendor_data: VendorUpdate,
    current_user: User = Depends(require_permission("vendors.update")),
    db: AsyncSession = Depends(get_db),
):
    """Update a vendor."""
    # Support both numeric DB ID and string vendor_id
    if vendor_id.isdigit():
        query = select(Vendor).where(
            Vendor.id == int(vendor_id),
            Vendor.deleted_at.is_(None)
        )
    else:
        query = select(Vendor).where(
            Vendor.vendor_id == vendor_id,
            Vendor.deleted_at.is_(None)
        )
    
    result = await db.execute(query)
    vendor = result.scalar_one_or_none()
    
    if not vendor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vendor not found",
        )
    
    # Update fields
    for field, value in vendor_data.model_dump(exclude_unset=True).items():
        if value is not None and hasattr(vendor, field):
            setattr(vendor, field, value)
    
    await db.commit()
    await db.refresh(vendor)
    
    return vendor_to_response(vendor)


@router.delete("/{vendor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vendor(
    vendor_id: str,
    current_user: User = Depends(require_permission("vendors.delete")),
    db: AsyncSession = Depends(get_db),
):
    """Soft delete a vendor."""
    # Support both numeric DB ID and string vendor_id
    if vendor_id.isdigit():
        query = select(Vendor).where(
            Vendor.id == int(vendor_id),
            Vendor.deleted_at.is_(None)
        )
    else:
        query = select(Vendor).where(
            Vendor.vendor_id == vendor_id,
            Vendor.deleted_at.is_(None)
        )
    
    result = await db.execute(query)
    vendor = result.scalar_one_or_none()
    
    if not vendor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vendor not found",
        )
    
    # Soft delete
    vendor.deleted_at = datetime.now(timezone.utc)
    vendor.is_active = False
    await db.commit()
