"""
System management endpoints.

CRUD operations for systems with lifecycle management.
"""

from typing import Optional, List
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.system import System, SystemStatus, BusinessProcess, Product
from app.models.audit import AuditLog, AuditAction
from app.auth.dependencies import (
    get_current_user,
    require_permission,
    get_client_ip,
    get_user_agent,
)
from app.schemas.system import (
    SystemCreate,
    SystemUpdate,
    SystemResponse,
    SystemDetailResponse,
    SystemListResponse,
    SystemDeprecateRequest,
)

router = APIRouter()


def can_access_system(user: User, system: System) -> bool:
    """Check if user can access a specific system."""
    # Admin, Compliance Officer, CISO can access all
    if user.role in {UserRole.ADMIN, UserRole.COMPLIANCE_OFFICER, UserRole.CISO}:
        return True
    
    # System owner can access their systems
    if system.owner_user_id == user.id:
        return True
    
    # Backup owner can access
    if system.backup_owner_id == user.id:
        return True
    
    # TODO: Check team membership
    
    return False


@router.get("", response_model=SystemListResponse)
async def list_systems(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: Optional[SystemStatus] = Query(None, alias="status"),
    team_id: Optional[int] = None,
    product_id: Optional[int] = None,
    search: Optional[str] = None,
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    List systems with pagination and filtering.
    
    System owners only see their systems.
    Admins and Compliance Officers see all.
    """
    query = select(System).where(System.deleted_at.is_(None))
    count_query = select(func.count(System.id)).where(System.deleted_at.is_(None))
    
    # Scope by user role
    if current_user.role == UserRole.SYSTEM_OWNER:
        query = query.where(
            (System.owner_user_id == current_user.id) |
            (System.backup_owner_id == current_user.id)
        )
        count_query = count_query.where(
            (System.owner_user_id == current_user.id) |
            (System.backup_owner_id == current_user.id)
        )
    
    # Apply filters
    if status_filter:
        query = query.where(System.status == status_filter)
        count_query = count_query.where(System.status == status_filter)
    
    if team_id:
        query = query.where(System.owner_team_id == team_id)
        count_query = count_query.where(System.owner_team_id == team_id)
    
    if search:
        search_filter = f"%{search.lower()}%"
        query = query.where(
            (System.system_id.ilike(search_filter)) |
            (System.display_name.ilike(search_filter))
        )
        count_query = count_query.where(
            (System.system_id.ilike(search_filter)) |
            (System.display_name.ilike(search_filter))
        )
    
    # Get total
    result = await db.execute(count_query)
    total = result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = (
        query
        .options(selectinload(System.owner_team), selectinload(System.owner_user))
        .offset(offset)
        .limit(per_page)
        .order_by(System.display_name)
    )
    
    result = await db.execute(query)
    systems = result.scalars().all()
    
    items = [
        SystemResponse(
            id=s.id,
            system_id=s.system_id,
            display_name=s.display_name,
            description=s.description,
            status=s.status,
            environment=s.environment,
            criticality=s.criticality,
            data_classifications=s.get_data_classifications(),
            owner_team=s.owner_team.name if s.owner_team else None,
            owner_user=s.owner_user.email if s.owner_user else None,
            business_process_count=len(s.business_processes),
            product_count=len(s.products),
            framework_count=len(s.frameworks),
            created_at=s.created_at,
            updated_at=s.updated_at,
            deprecated_at=s.deprecated_at,
        )
        for s in systems
    ]
    
    pages = (total + per_page - 1) // per_page if per_page > 0 else 0
    
    return SystemListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.post("", response_model=SystemResponse, status_code=status.HTTP_201_CREATED)
async def create_system(
    request: Request,
    system_data: SystemCreate,
    current_user: User = Depends(require_permission("systems.create")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new system.
    
    Requires: systems.create permission (Admin, Compliance Officer)
    """
    # Check if system_id already exists
    result = await db.execute(
        select(System).where(System.system_id == system_data.system_id)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"System with ID '{system_data.system_id}' already exists",
        )
    
    # Create system
    system = System(
        system_id=system_data.system_id,
        display_name=system_data.display_name,
        description=system_data.description,
        status=SystemStatus.ACTIVE,
        environment=system_data.environment,
        criticality=system_data.criticality,
        owner_team_id=system_data.owner_team_id,
        owner_user_id=system_data.owner_user_id,
        backup_owner_id=system_data.backup_owner_id,
        ingest_source=system_data.ingest_source,
        sbom_url=system_data.sbom_url,
        cmdb_link=system_data.cmdb_link,
        created_by_id=current_user.id,
    )
    
    if system_data.data_classifications:
        system.set_data_classifications(system_data.data_classifications)
    
    # Add business processes
    if system_data.business_process_ids:
        result = await db.execute(
            select(BusinessProcess).where(BusinessProcess.id.in_(system_data.business_process_ids))
        )
        system.business_processes = list(result.scalars().all())
    
    # Add to products
    if system_data.product_ids:
        result = await db.execute(
            select(Product).where(Product.id.in_(system_data.product_ids))
        )
        system.products = list(result.scalars().all())
    
    db.add(system)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.SYSTEM_CREATED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="system",
        resource_id=system_data.system_id,
        resource_name=system_data.display_name,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(system)
    
    return SystemResponse(
        id=system.id,
        system_id=system.system_id,
        display_name=system.display_name,
        description=system.description,
        status=system.status,
        environment=system.environment,
        criticality=system.criticality,
        data_classifications=system.get_data_classifications(),
        created_at=system.created_at,
        updated_at=system.updated_at,
    )


@router.get("/{system_id}", response_model=SystemDetailResponse)
async def get_system(
    system_id: str,
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific system by ID (supports both numeric DB id and string system_id)."""
    # Support both numeric DB ID and string system_id
    if system_id.isdigit():
        # Numeric ID - look up by database primary key
        query = select(System).where(System.id == int(system_id), System.deleted_at.is_(None))
    else:
        # String ID - look up by system_id field
        query = select(System).where(System.system_id == system_id, System.deleted_at.is_(None))
    
    result = await db.execute(
        query.options(
            selectinload(System.owner_team),
            selectinload(System.owner_user),
            selectinload(System.business_processes),
            selectinload(System.products),
            selectinload(System.frameworks),
        )
    )
    system = result.scalar_one_or_none()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found",
        )
    
    # Check access for system owners
    if current_user.role == UserRole.SYSTEM_OWNER:
        if not can_access_system(current_user, system):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this system",
            )
    
    return SystemDetailResponse(
        id=system.id,
        system_id=system.system_id,
        display_name=system.display_name,
        description=system.description,
        status=system.status,
        environment=system.environment,
        criticality=system.criticality,
        data_classifications=system.get_data_classifications(),
        owner_team=system.owner_team.name if system.owner_team else None,
        owner_user=system.owner_user.email if system.owner_user else None,
        business_process_count=len(system.business_processes),
        product_count=len(system.products),
        framework_count=len(system.frameworks),
        business_processes=[p.name for p in system.business_processes],
        products=[p.display_name for p in system.products],
        frameworks=[f.framework_id for f in system.frameworks],
        deprecation_reason=system.deprecation_reason,
        scheduled_archive_date=system.scheduled_archive_date,
        ingest_source=system.ingest_source,
        sbom_url=system.sbom_url,
        cmdb_link=system.cmdb_link,
        created_at=system.created_at,
        updated_at=system.updated_at,
        deprecated_at=system.deprecated_at,
    )


@router.patch("/{system_id}", response_model=SystemResponse)
async def update_system(
    request: Request,
    system_id: str,
    system_data: SystemUpdate,
    current_user: User = Depends(require_permission("systems.update")),
    db: AsyncSession = Depends(get_db),
):
    """Update a system."""
    result = await db.execute(
        select(System).where(System.system_id == system_id, System.deleted_at.is_(None))
    )
    system = result.scalar_one_or_none()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found",
        )
    
    # Check access for system owners
    if current_user.role == UserRole.SYSTEM_OWNER:
        if not can_access_system(current_user, system):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update this system",
            )
    
    # Update fields
    if system_data.display_name is not None:
        system.display_name = system_data.display_name
    if system_data.description is not None:
        system.description = system_data.description
    if system_data.status is not None:
        system.status = system_data.status
    if system_data.environment is not None:
        system.environment = system_data.environment
    if system_data.criticality is not None:
        system.criticality = system_data.criticality
    if system_data.data_classifications is not None:
        system.set_data_classifications(system_data.data_classifications)
    if system_data.owner_team_id is not None:
        system.owner_team_id = system_data.owner_team_id
    if system_data.owner_user_id is not None:
        system.owner_user_id = system_data.owner_user_id
    if system_data.ingest_source is not None:
        system.ingest_source = system_data.ingest_source
    if system_data.sbom_url is not None:
        system.sbom_url = system_data.sbom_url
    if system_data.cmdb_link is not None:
        system.cmdb_link = system_data.cmdb_link
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.SYSTEM_UPDATED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="system",
        resource_id=system.system_id,
        resource_name=system.display_name,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(system)
    
    return SystemResponse(
        id=system.id,
        system_id=system.system_id,
        display_name=system.display_name,
        description=system.description,
        status=system.status,
        environment=system.environment,
        criticality=system.criticality,
        data_classifications=system.get_data_classifications(),
        created_at=system.created_at,
        updated_at=system.updated_at,
        deprecated_at=system.deprecated_at,
    )


@router.post("/{system_id}/deprecate", response_model=SystemResponse)
async def deprecate_system(
    request: Request,
    system_id: str,
    deprecate_data: SystemDeprecateRequest,
    current_user: User = Depends(require_permission("systems.update")),
    db: AsyncSession = Depends(get_db),
):
    """Mark a system as deprecated."""
    result = await db.execute(
        select(System).where(System.system_id == system_id, System.deleted_at.is_(None))
    )
    system = result.scalar_one_or_none()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found",
        )
    
    # Find replacement system if specified
    replacement_id = None
    if deprecate_data.replacement_system_id:
        result = await db.execute(
            select(System).where(System.system_id == deprecate_data.replacement_system_id)
        )
        replacement = result.scalar_one_or_none()
        if replacement:
            replacement_id = replacement.id
    
    # Deprecate
    system.deprecate(deprecate_data.reason, replacement_id)
    system.scheduled_archive_date = deprecate_data.scheduled_archive_date
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.SYSTEM_DEPRECATED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="system",
        resource_id=system.system_id,
        resource_name=system.display_name,
        details={"reason": deprecate_data.reason},
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(system)
    
    # TODO: Send notification to owner if deprecate_data.notify_owner
    
    return SystemResponse(
        id=system.id,
        system_id=system.system_id,
        display_name=system.display_name,
        description=system.description,
        status=system.status,
        environment=system.environment,
        criticality=system.criticality,
        data_classifications=system.get_data_classifications(),
        created_at=system.created_at,
        updated_at=system.updated_at,
        deprecated_at=system.deprecated_at,
    )


@router.post("/{system_id}/archive", status_code=status.HTTP_204_NO_CONTENT)
async def archive_system(
    request: Request,
    system_id: str,
    current_user: User = Depends(require_permission("systems.delete")),
    db: AsyncSession = Depends(get_db),
):
    """Archive a system (soft delete with preservation)."""
    result = await db.execute(
        select(System).where(System.system_id == system_id, System.deleted_at.is_(None))
    )
    system = result.scalar_one_or_none()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found",
        )
    
    system.archive()
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.SYSTEM_ARCHIVED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="system",
        resource_id=system.system_id,
        resource_name=system.display_name,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()

