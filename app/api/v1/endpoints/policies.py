"""
Policy Management API.

CRUD operations for SHACL policies and Gemara-compiled rules.
"""

import os
import uuid
from typing import Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.config import DATA_DIR
from app.models.user import User
from app.models.policy import Policy, PolicyType
from app.models.audit import AuditLog, AuditAction
from app.auth.dependencies import require_permission, get_client_ip, get_user_agent
from app.schemas.common import PaginatedResponse
from app.schemas.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    PolicyValidationResult,
)

router = APIRouter()

# Directory for policy files
POLICIES_DIR = DATA_DIR / "policies"


@router.get("", response_model=PaginatedResponse[PolicyResponse])
async def list_policies(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    policy_type: Optional[PolicyType] = None,
    framework: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: User = Depends(require_permission("policies.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    List all policies with pagination and filtering.
    """
    query = select(Policy)
    count_query = select(func.count(Policy.id))
    
    # Apply filters
    if policy_type:
        query = query.where(Policy.policy_type == policy_type)
        count_query = count_query.where(Policy.policy_type == policy_type)
    
    if framework:
        query = query.where(Policy.framework.ilike(f"%{framework}%"))
        count_query = count_query.where(Policy.framework.ilike(f"%{framework}%"))
    
    if is_active is not None:
        query = query.where(Policy.is_active == is_active)
        count_query = count_query.where(Policy.is_active == is_active)
    
    # Get total
    result = await db.execute(count_query)
    total = result.scalar() or 0
    
    # Paginate
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page).order_by(Policy.name)
    
    result = await db.execute(query)
    policies = result.scalars().all()
    
    return PaginatedResponse.create(
        items=[
            PolicyResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                policy_type=p.policy_type.value,
                framework=p.framework,
                version=p.version,
                is_active=p.is_active,
                file_path=p.file_path,
                created_by=None,  # Would need to join with users
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in policies
        ],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    policy_type: PolicyType = Form(PolicyType.SHACL),
    framework: Optional[str] = Form(None),
    version: str = Form("1.0.0"),
    policy_file: UploadFile = File(..., description="TTL file containing SHACL shapes"),
    current_user: User = Depends(require_permission("policies.create")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new policy by uploading a SHACL TTL file.
    
    The file will be validated and stored.
    """
    # Validate file type
    if not policy_file.filename.endswith(('.ttl', '.turtle', '.rdf')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy file must be a Turtle (.ttl) or RDF file",
        )
    
    # Read and validate content
    content = await policy_file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy file must be valid UTF-8 text",
        )
    
    # Validate as RDF
    validation = validate_shacl_content(content_str)
    if not validation.valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid SHACL policy: {validation.errors}",
        )
    
    # Save file
    POLICIES_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = f"{uuid.uuid4()}_{policy_file.filename}"
    file_path = POLICIES_DIR / safe_name
    
    with open(file_path, 'wb') as f:
        f.write(content)
    
    # Create database record
    policy = Policy(
        name=name,
        description=description,
        policy_type=policy_type,
        framework=framework,
        version=version,
        file_path=str(file_path),
        is_active=True,
        created_by_id=current_user.id,
    )
    
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        policy_type=policy.policy_type.value,
        framework=policy.framework,
        version=policy.version,
        is_active=policy.is_active,
        file_path=policy.file_path,
        created_by=current_user.email,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: int,
    current_user: User = Depends(require_permission("policies.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific policy by ID."""
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        policy_type=policy.policy_type.value,
        framework=policy.framework,
        version=policy.version,
        is_active=policy.is_active,
        file_path=policy.file_path,
        created_by=None,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.get("/{policy_id}/content", response_class=PlainTextResponse)
async def get_policy_content(
    policy_id: int,
    current_user: User = Depends(require_permission("policies.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get the raw TTL content of a policy."""
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    
    if not policy.file_path or not os.path.exists(policy.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy file not found on disk",
        )
    
    with open(policy.file_path, 'r') as f:
        return f.read()


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: int,
    policy_data: PolicyUpdate,
    current_user: User = Depends(require_permission("policies.update")),
    db: AsyncSession = Depends(get_db),
):
    """Update policy metadata."""
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    
    # Update fields
    if policy_data.name is not None:
        policy.name = policy_data.name
    if policy_data.description is not None:
        policy.description = policy_data.description
    if policy_data.framework is not None:
        policy.framework = policy_data.framework
    if policy_data.version is not None:
        policy.version = policy_data.version
    if policy_data.is_active is not None:
        policy.is_active = policy_data.is_active
    
    await db.commit()
    await db.refresh(policy)
    
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        policy_type=policy.policy_type.value,
        framework=policy.framework,
        version=policy.version,
        is_active=policy.is_active,
        file_path=policy.file_path,
        created_by=None,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: int,
    current_user: User = Depends(require_permission("policies.delete")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a policy."""
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    
    # Delete file if exists
    if policy.file_path and os.path.exists(policy.file_path):
        os.remove(policy.file_path)
    
    await db.delete(policy)
    await db.commit()


@router.post("/validate", response_model=PolicyValidationResult)
async def validate_policy(
    policy_file: UploadFile = File(..., description="TTL file to validate"),
    current_user: User = Depends(require_permission("policies.read")),
):
    """
    Validate a SHACL policy file without saving it.
    
    Checks for:
    - Valid RDF syntax
    - Valid SHACL shapes
    - Target classes and properties
    """
    content = await policy_file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        return PolicyValidationResult(
            valid=False,
            errors=["File must be valid UTF-8 text"],
        )
    
    return validate_shacl_content(content_str)


def validate_shacl_content(content: str) -> PolicyValidationResult:
    """Validate SHACL content and extract metadata."""
    from rdflib import Graph, Namespace
    from rdflib.namespace import RDF
    
    SH = Namespace("http://www.w3.org/ns/shacl#")
    
    errors = []
    warnings = []
    shape_count = 0
    target_classes = []
    
    g = Graph()
    try:
        g.parse(data=content, format='turtle')
    except Exception as e:
        return PolicyValidationResult(
            valid=False,
            errors=[f"RDF parse error: {str(e)}"],
        )
    
    # Count shapes
    for shape in g.subjects(RDF.type, SH.NodeShape):
        shape_count += 1
        
        # Get target class if defined
        for target in g.objects(shape, SH.targetClass):
            target_classes.append(str(target).split("#")[-1])
    
    for shape in g.subjects(RDF.type, SH.PropertyShape):
        shape_count += 1
    
    if shape_count == 0:
        warnings.append("No SHACL shapes found in the file")
    
    return PolicyValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        shape_count=shape_count,
        target_classes=list(set(target_classes)),
    )


@router.get("/active/all")
async def get_active_policies(
    current_user: User = Depends(require_permission("policies.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all active policies for use in compliance checks.
    
    Returns file paths that can be loaded by the engine.
    """
    result = await db.execute(
        select(Policy).where(Policy.is_active == True)
    )
    policies = result.scalars().all()
    
    return {
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "file_path": p.file_path,
                "framework": p.framework,
            }
            for p in policies
            if p.file_path and os.path.exists(p.file_path)
        ]
    }

