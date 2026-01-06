"""
User management endpoints.

Requires admin or compliance officer role for most operations.
"""

from typing import List, Optional

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.user import User, UserRole, Team
from app.models.audit import AuditLog, AuditAction
from app.auth.dependencies import (
    get_current_user,
    require_permission,
)
from app.auth.password import generate_temp_password
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    TeamResponse,
    user_to_response,
)
from app.schemas.common import PaginatedResponse
from app.auth.audit import create_audit_log

router = APIRouter()


# =============================================================================
# User CRUD
# =============================================================================

@router.get("", response_model=PaginatedResponse[UserResponse])
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: User = Depends(require_permission("users.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    List all users with pagination and filtering.
    
    Requires: users.read permission
    """
    # Build query
    query = select(User).where(User.deleted_at.is_(None))
    count_query = select(func.count(User.id)).where(User.deleted_at.is_(None))
    
    # Apply filters
    if role:
        query = query.where(User.role == role)
        count_query = count_query.where(User.role == role)
    
    if is_active is not None:
        query = query.where(User.is_active == is_active)
        count_query = count_query.where(User.is_active == is_active)
    
    if search:
        search_filter = f"%{search.lower()}%"
        query = query.where(
            (User.email.ilike(search_filter)) |
            (User.full_name.ilike(search_filter))
        )
        count_query = count_query.where(
            (User.email.ilike(search_filter)) |
            (User.full_name.ilike(search_filter))
        )
    
    # Get total count
    result = await db.execute(count_query)
    total = result.scalar()
    
    # Apply pagination and eager load teams relationship
    offset = (page - 1) * per_page
    query = (
        query
        .options(selectinload(User.teams))
        .offset(offset)
        .limit(per_page)
        .order_by(User.created_at.desc())
    )
    
    result = await db.execute(query)
    users = result.scalars().all()
    
    # Convert to response using helper
    items = [user_to_response(user) for user in users]
    
    return PaginatedResponse.create(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    user_data: UserCreate,
    current_user: User = Depends(require_permission("users.create")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new user.
    
    Requires: users.create permission (Admin only)
    
    If no password is provided, a temporary password will be generated.
    """
    # Check if email already exists
    result = await db.execute(
        select(User).where(User.email == user_data.email.lower())
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # Create user
    user = User(
        email=user_data.email.lower(),
        full_name=user_data.full_name,
        role=user_data.role,
        is_active=True,
        is_verified=False,
    )
    
    # Set password
    if user_data.password:
        user.set_password(user_data.password)
        temp_password = None
    else:
        temp_password = generate_temp_password()
        user.set_password(temp_password)
    
    # Add to teams
    if user_data.team_ids:
        result = await db.execute(
            select(Team).where(Team.id.in_(user_data.team_ids))
        )
        teams = result.scalars().all()
        user.teams = list(teams)
    
    db.add(user)
    
    # Audit log using helper
    audit = create_audit_log(
        request=request,
        user=current_user,
        action=AuditAction.USER_CREATED,
        resource_type="user",
        resource_id=user_data.email,
        resource_name=user_data.full_name,
        details={"role": user_data.role.value},
    )
    db.add(audit)
    
    await db.commit()
    
    # Re-query with eager loading to avoid lazy load issues
    result = await db.execute(
        select(User).where(User.id == user.id).options(selectinload(User.teams))
    )
    user = result.scalar_one()
    
    # TODO: Send welcome email with temp_password if send_welcome_email is True
    
    return user_to_response(user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(require_permission("users.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get a specific user by ID.
    
    Requires: users.read permission
    """
    result = await db.execute(
        select(User)
        .where(User.id == user_id, User.deleted_at.is_(None))
        .options(selectinload(User.teams))
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    return user_to_response(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(require_permission("users.update")),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a user.
    
    Requires: users.update permission
    """
    result = await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Prevent demoting yourself if you're the last admin
    if user.id == current_user.id and user_data.role and user_data.role != UserRole.ADMIN:
        # Check if there are other admins
        result = await db.execute(
            select(func.count(User.id)).where(
                User.role == UserRole.ADMIN,
                User.is_active == True,
                User.deleted_at.is_(None),
            )
        )
        admin_count = result.scalar()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last admin",
            )
    
    # Track role change for audit
    old_role = user.role
    role_changed = False
    
    # Update fields
    if user_data.email is not None:
        # Check email uniqueness
        result = await db.execute(
            select(User).where(User.email == user_data.email.lower(), User.id != user_id)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use",
            )
        user.email = user_data.email.lower()
    
    if user_data.full_name is not None:
        user.full_name = user_data.full_name
    
    if user_data.role is not None:
        role_changed = user_data.role != old_role
        user.role = user_data.role
    
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    
    if user_data.team_ids is not None:
        result = await db.execute(
            select(Team).where(Team.id.in_(user_data.team_ids))
        )
        teams = result.scalars().all()
        user.teams = list(teams)
    
    # Audit log using helper
    action = AuditAction.USER_ROLE_CHANGED if role_changed else AuditAction.USER_UPDATED
    audit = create_audit_log(
        request=request,
        user=current_user,
        action=action,
        resource_type="user",
        resource_id=str(user.id),
        resource_name=user.email,
        details={
            "old_role": old_role.value if role_changed else None,
            "new_role": user.role.value if role_changed else None,
        },
    )
    db.add(audit)
    
    await db.commit()
    
    # Re-query with eager loading to avoid lazy load issues
    result = await db.execute(
        select(User).where(User.id == user.id).options(selectinload(User.teams))
    )
    user = result.scalar_one()
    
    return user_to_response(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_permission("users.delete")),
    db: AsyncSession = Depends(get_db),
):
    """
    Soft-delete a user.
    
    Requires: users.delete permission (Admin only)
    """
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself",
        )
    
    result = await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Soft delete
    user.deleted_at = datetime.now(timezone.utc)
    user.is_active = False
    
    # Audit log using helper
    audit = create_audit_log(
        request=request,
        user=current_user,
        action=AuditAction.USER_DELETED,
        resource_type="user",
        resource_id=str(user.id),
        resource_name=user.email,
    )
    db.add(audit)
    
    await db.commit()


# =============================================================================
# Team Management
# =============================================================================

@router.get("/teams", response_model=List[TeamResponse])
async def list_teams(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all teams."""
    result = await db.execute(select(Team).order_by(Team.name))
    teams = result.scalars().all()
    
    return [
        TeamResponse(
            id=team.id,
            name=team.name,
            description=team.description,
            member_count=len(team.members),
            created_at=team.created_at,
        )
        for team in teams
    ]

