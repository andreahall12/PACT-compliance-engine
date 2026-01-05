"""
Document and Evidence management endpoints.

Handles:
- Document upload/download
- Evidence requests from auditors
- Evidence package generation
"""

import hashlib
import os
import secrets
from datetime import datetime, timezone, date
from typing import Optional, List
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.config import BASE_DIR
from app.models.user import User, UserRole
from app.models.document import (
    Document, DocumentType, DocumentStatus, DocumentVisibility,
    EvidenceRequest, EvidenceRequestStatus,
)
from app.models.audit import AuditLog, AuditAction
from app.auth.dependencies import (
    get_current_user,
    require_permission,
    get_client_ip,
    get_user_agent,
)
from app.schemas.document import (
    DocumentCreate,
    DocumentUpdate,
    DocumentResponse,
    DocumentListResponse,
    DocumentUploadResponse,
    EvidenceRequestCreate,
    EvidenceRequestUpdate,
    EvidenceRequestResponse,
    EvidenceRequestListResponse,
)

router = APIRouter()

# Document storage configuration
DOCUMENTS_DIR = BASE_DIR / "data" / "documents"
DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt",
    "png", "jpg", "jpeg", "gif",
    "txt", "md", "csv", "json", "xml",
}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


def get_safe_filename(filename: str) -> str:
    """Generate a safe filename while preserving extension."""
    # Get extension
    ext = Path(filename).suffix.lower()
    # Generate random name
    safe_name = secrets.token_urlsafe(16)
    return f"{safe_name}{ext}"


def validate_file(file: UploadFile) -> None:
    """Validate uploaded file."""
    # Check extension
    ext = Path(file.filename).suffix.lower().lstrip(".")
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type '{ext}' not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
        )
    
    # Check content type
    allowed_content_types = {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "image/png", "image/jpeg", "image/gif",
        "text/plain", "text/markdown", "text/csv",
        "application/json", "application/xml", "text/xml",
    }
    if file.content_type and file.content_type not in allowed_content_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Content type '{file.content_type}' not allowed",
        )


# =============================================================================
# Document CRUD
# =============================================================================

@router.get("", response_model=DocumentListResponse)
async def list_documents(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    document_type: Optional[DocumentType] = None,
    status_filter: Optional[DocumentStatus] = Query(None, alias="status"),
    system_id: Optional[int] = None,
    control: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(require_permission("documents.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    List documents with pagination and filtering.
    
    External auditors only see documents shared with auditors.
    """
    query = select(Document).where(Document.deleted_at.is_(None))
    count_query = select(func.count(Document.id)).where(Document.deleted_at.is_(None))
    
    # External auditors only see shared documents
    if current_user.role == UserRole.EXTERNAL_AUDITOR:
        query = query.where(Document.share_with_auditors == True)
        count_query = count_query.where(Document.share_with_auditors == True)
    
    # Apply filters
    if document_type:
        query = query.where(Document.document_type == document_type)
        count_query = count_query.where(Document.document_type == document_type)
    
    if status_filter:
        query = query.where(Document.status == status_filter)
        count_query = count_query.where(Document.status == status_filter)
    
    if system_id:
        query = query.where(Document.system_id == system_id)
        count_query = count_query.where(Document.system_id == system_id)
    
    if control:
        # Search in JSON array
        query = query.where(Document.controls.contains(control))
        count_query = count_query.where(Document.controls.contains(control))
    
    if search:
        search_filter = f"%{search.lower()}%"
        query = query.where(
            (Document.title.ilike(search_filter)) |
            (Document.description.ilike(search_filter))
        )
        count_query = count_query.where(
            (Document.title.ilike(search_filter)) |
            (Document.description.ilike(search_filter))
        )
    
    # Get total
    result = await db.execute(count_query)
    total = result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = (
        query
        .options(selectinload(Document.uploaded_by), selectinload(Document.system))
        .offset(offset)
        .limit(per_page)
        .order_by(Document.created_at.desc())
    )
    
    result = await db.execute(query)
    documents = result.scalars().all()
    
    items = [
        DocumentResponse(
            id=d.id,
            title=d.title,
            description=d.description,
            file_name=d.file_name,
            file_type=d.file_type,
            file_size_bytes=d.file_size_bytes,
            document_type=d.document_type,
            status=d.status,
            effective_date=d.effective_date,
            review_date=d.review_date,
            expiration_date=d.expiration_date,
            captured_at=d.captured_at,
            controls=d.get_controls(),
            system_id=d.system_id,
            system_name=d.system.display_name if d.system else None,
            visibility=d.visibility,
            share_with_auditors=d.share_with_auditors,
            version=d.version,
            has_previous_version=d.previous_version_id is not None,
            uploaded_by=d.uploaded_by.email,
            approved_by=d.approved_by.email if d.approved_by else None,
            approved_at=d.approved_at,
            created_at=d.created_at,
            updated_at=d.updated_at,
            is_expired=d.is_expired(),
            needs_review=d.needs_review(),
        )
        for d in documents
    ]
    
    pages = (total + per_page - 1) // per_page if per_page > 0 else 0
    
    return DocumentListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.post("", response_model=DocumentUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Query(..., min_length=3, max_length=255),
    document_type: DocumentType = Query(...),
    description: Optional[str] = Query(None, max_length=2000),
    controls: Optional[str] = Query(None, description="Comma-separated control IDs"),
    system_id: Optional[int] = Query(None),
    effective_date: Optional[date] = Query(None),
    review_date: Optional[date] = Query(None),
    expiration_date: Optional[date] = Query(None),
    share_with_auditors: bool = Query(True),
    current_user: User = Depends(require_permission("documents.create")),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload a new document.
    
    File is validated and stored securely.
    SHA-256 hash is computed for integrity verification.
    """
    # Validate file
    validate_file(file)
    
    # Read file content
    content = await file.read()
    
    # Check size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB",
        )
    
    # Compute hash
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Generate safe filename
    safe_filename = get_safe_filename(file.filename)
    storage_path = DOCUMENTS_DIR / safe_filename
    
    # Save file
    with open(storage_path, "wb") as f:
        f.write(content)
    
    # Parse controls
    control_list = []
    if controls:
        control_list = [c.strip() for c in controls.split(",") if c.strip()]
    
    # Create document record
    doc = Document(
        title=title,
        description=description,
        file_name=file.filename,
        file_type=Path(file.filename).suffix.lower().lstrip("."),
        file_size_bytes=len(content),
        file_hash=file_hash,
        storage_path=str(storage_path),
        document_type=document_type,
        status=DocumentStatus.DRAFT,
        effective_date=effective_date,
        review_date=review_date,
        expiration_date=expiration_date,
        visibility=DocumentVisibility.INTERNAL,
        share_with_auditors=share_with_auditors,
        uploaded_by_id=current_user.id,
    )
    
    if control_list:
        doc.set_controls(control_list)
    
    if system_id:
        doc.system_id = system_id
    
    db.add(doc)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.DOCUMENT_UPLOADED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="document",
        resource_name=title,
        details={"file_name": file.filename, "file_size": len(content)},
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(doc)
    
    return DocumentUploadResponse(
        id=doc.id,
        title=doc.title,
        file_name=doc.file_name,
        file_size_bytes=doc.file_size_bytes,
        status=doc.status,
    )


@router.get("/{document_id}")
async def get_document(
    document_id: int,
    current_user: User = Depends(require_permission("documents.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get document metadata."""
    result = await db.execute(
        select(Document)
        .where(Document.id == document_id, Document.deleted_at.is_(None))
        .options(selectinload(Document.uploaded_by), selectinload(Document.system))
    )
    doc = result.scalar_one_or_none()
    
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    
    # Check access for external auditors
    if current_user.role == UserRole.EXTERNAL_AUDITOR and not doc.share_with_auditors:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this document",
        )
    
    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        file_name=doc.file_name,
        file_type=doc.file_type,
        file_size_bytes=doc.file_size_bytes,
        document_type=doc.document_type,
        status=doc.status,
        effective_date=doc.effective_date,
        review_date=doc.review_date,
        expiration_date=doc.expiration_date,
        captured_at=doc.captured_at,
        controls=doc.get_controls(),
        system_id=doc.system_id,
        system_name=doc.system.display_name if doc.system else None,
        visibility=doc.visibility,
        share_with_auditors=doc.share_with_auditors,
        version=doc.version,
        has_previous_version=doc.previous_version_id is not None,
        uploaded_by=doc.uploaded_by.email,
        approved_by=doc.approved_by.email if doc.approved_by else None,
        approved_at=doc.approved_at,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        is_expired=doc.is_expired(),
        needs_review=doc.needs_review(),
    )


@router.get("/{document_id}/download")
async def download_document(
    request: Request,
    document_id: int,
    current_user: User = Depends(require_permission("documents.read")),
    db: AsyncSession = Depends(get_db),
):
    """Download document file."""
    result = await db.execute(
        select(Document).where(Document.id == document_id, Document.deleted_at.is_(None))
    )
    doc = result.scalar_one_or_none()
    
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    
    # Check access
    if current_user.role == UserRole.EXTERNAL_AUDITOR and not doc.share_with_auditors:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to download this document",
        )
    
    # Check file exists
    if not os.path.exists(doc.storage_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk",
        )
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.DOCUMENT_DOWNLOADED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="document",
        resource_id=str(doc.id),
        resource_name=doc.title,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    await db.commit()
    
    return FileResponse(
        path=doc.storage_path,
        filename=doc.file_name,
        media_type="application/octet-stream",
    )


@router.patch("/{document_id}", response_model=DocumentResponse)
async def update_document(
    request: Request,
    document_id: int,
    doc_data: DocumentUpdate,
    current_user: User = Depends(require_permission("documents.update")),
    db: AsyncSession = Depends(get_db),
):
    """Update document metadata."""
    result = await db.execute(
        select(Document)
        .where(Document.id == document_id, Document.deleted_at.is_(None))
        .options(selectinload(Document.uploaded_by))
    )
    doc = result.scalar_one_or_none()
    
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    
    # Update fields
    if doc_data.title is not None:
        doc.title = doc_data.title
    if doc_data.description is not None:
        doc.description = doc_data.description
    if doc_data.status is not None:
        doc.status = doc_data.status
    if doc_data.effective_date is not None:
        doc.effective_date = doc_data.effective_date
    if doc_data.review_date is not None:
        doc.review_date = doc_data.review_date
    if doc_data.expiration_date is not None:
        doc.expiration_date = doc_data.expiration_date
    if doc_data.controls is not None:
        doc.set_controls(doc_data.controls)
    if doc_data.visibility is not None:
        doc.visibility = doc_data.visibility
    if doc_data.share_with_auditors is not None:
        doc.share_with_auditors = doc_data.share_with_auditors
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.DOCUMENT_UPDATED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="document",
        resource_id=str(doc.id),
        resource_name=doc.title,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(doc)
    
    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        file_name=doc.file_name,
        file_type=doc.file_type,
        file_size_bytes=doc.file_size_bytes,
        document_type=doc.document_type,
        status=doc.status,
        effective_date=doc.effective_date,
        review_date=doc.review_date,
        expiration_date=doc.expiration_date,
        captured_at=doc.captured_at,
        controls=doc.get_controls(),
        system_id=doc.system_id,
        visibility=doc.visibility,
        share_with_auditors=doc.share_with_auditors,
        version=doc.version,
        has_previous_version=doc.previous_version_id is not None,
        uploaded_by=doc.uploaded_by.email,
        approved_by=doc.approved_by.email if doc.approved_by else None,
        approved_at=doc.approved_at,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        is_expired=doc.is_expired(),
        needs_review=doc.needs_review(),
    )


@router.post("/{document_id}/approve", response_model=DocumentResponse)
async def approve_document(
    request: Request,
    document_id: int,
    current_user: User = Depends(require_permission("documents.update")),
    db: AsyncSession = Depends(get_db),
):
    """Approve and publish a document."""
    result = await db.execute(
        select(Document)
        .where(Document.id == document_id, Document.deleted_at.is_(None))
        .options(selectinload(Document.uploaded_by))
    )
    doc = result.scalar_one_or_none()
    
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    
    doc.status = DocumentStatus.PUBLISHED
    doc.approved_by_id = current_user.id
    doc.approved_at = datetime.now(timezone.utc)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.DOCUMENT_APPROVED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="document",
        resource_id=str(doc.id),
        resource_name=doc.title,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(doc)
    
    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description,
        file_name=doc.file_name,
        file_type=doc.file_type,
        file_size_bytes=doc.file_size_bytes,
        document_type=doc.document_type,
        status=doc.status,
        effective_date=doc.effective_date,
        review_date=doc.review_date,
        expiration_date=doc.expiration_date,
        captured_at=doc.captured_at,
        controls=doc.get_controls(),
        system_id=doc.system_id,
        visibility=doc.visibility,
        share_with_auditors=doc.share_with_auditors,
        version=doc.version,
        has_previous_version=doc.previous_version_id is not None,
        uploaded_by=doc.uploaded_by.email,
        approved_by=current_user.email,
        approved_at=doc.approved_at,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        is_expired=doc.is_expired(),
        needs_review=doc.needs_review(),
    )


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    request: Request,
    document_id: int,
    current_user: User = Depends(require_permission("documents.delete")),
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete a document."""
    result = await db.execute(
        select(Document).where(Document.id == document_id, Document.deleted_at.is_(None))
    )
    doc = result.scalar_one_or_none()
    
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    
    doc.deleted_at = datetime.now(timezone.utc)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.DOCUMENT_DELETED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="document",
        resource_id=str(doc.id),
        resource_name=doc.title,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()


# =============================================================================
# Evidence Requests
# =============================================================================

@router.get("/requests", response_model=EvidenceRequestListResponse)
async def list_evidence_requests(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    assigned_to_me: bool = Query(False),
    current_user: User = Depends(require_permission("evidence.request")),
    db: AsyncSession = Depends(get_db),
):
    """List evidence requests."""
    query = select(EvidenceRequest)
    count_query = select(func.count(EvidenceRequest.id))
    
    if status_filter:
        query = query.where(EvidenceRequest.status == status_filter)
        count_query = count_query.where(EvidenceRequest.status == status_filter)
    
    if assigned_to_me:
        query = query.where(EvidenceRequest.assigned_to_id == current_user.id)
        count_query = count_query.where(EvidenceRequest.assigned_to_id == current_user.id)
    
    # Get total
    result = await db.execute(count_query)
    total = result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = (
        query
        .options(
            selectinload(EvidenceRequest.requested_by),
            selectinload(EvidenceRequest.assigned_to),
        )
        .offset(offset)
        .limit(per_page)
        .order_by(EvidenceRequest.due_date)
    )
    
    result = await db.execute(query)
    requests = result.scalars().all()
    
    items = [
        EvidenceRequestResponse(
            id=r.id,
            audit_name=r.audit_name,
            control_id=r.control_id,
            description=r.description,
            priority=r.priority.value,
            due_date=r.due_date,
            requested_by=r.requested_by.email,
            requested_at=r.requested_at,
            assigned_to=r.assigned_to.email if r.assigned_to else None,
            status=r.status.value,
            is_overdue=r.is_overdue(),
            response_notes=r.response_notes,
            responded_at=r.responded_at,
            reviewed_by=r.reviewed_by.email if r.reviewed_by else None,
            reviewed_at=r.reviewed_at,
            review_notes=r.review_notes,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in requests
    ]
    
    pages = (total + per_page - 1) // per_page if per_page > 0 else 0
    
    return EvidenceRequestListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.post("/requests", response_model=EvidenceRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_evidence_request(
    request: Request,
    req_data: EvidenceRequestCreate,
    current_user: User = Depends(require_permission("evidence.request")),
    db: AsyncSession = Depends(get_db),
):
    """Create an evidence request (typically by auditors)."""
    from app.models.document import EvidenceRequestPriority
    
    evidence_req = EvidenceRequest(
        audit_name=req_data.audit_name,
        control_id=req_data.control_id,
        description=req_data.description,
        priority=EvidenceRequestPriority(req_data.priority),
        due_date=req_data.due_date,
        requested_by_id=current_user.id,
        assigned_to_id=req_data.assigned_to_id,
        status=EvidenceRequestStatus.PENDING,
    )
    
    db.add(evidence_req)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.EVIDENCE_REQUESTED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="evidence_request",
        resource_name=f"{req_data.audit_name} - {req_data.control_id}",
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(evidence_req)
    
    return EvidenceRequestResponse(
        id=evidence_req.id,
        audit_name=evidence_req.audit_name,
        control_id=evidence_req.control_id,
        description=evidence_req.description,
        priority=evidence_req.priority.value,
        due_date=evidence_req.due_date,
        requested_by=current_user.email,
        requested_at=evidence_req.requested_at,
        status=evidence_req.status.value,
        is_overdue=evidence_req.is_overdue(),
        created_at=evidence_req.created_at,
        updated_at=evidence_req.updated_at,
    )

