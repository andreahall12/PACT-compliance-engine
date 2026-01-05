"""
Document and Evidence request schemas.
"""

from typing import Optional, List
from datetime import datetime, date
from pydantic import BaseModel, Field, field_validator
import re

from app.models.document import DocumentType, DocumentStatus, DocumentVisibility


class DocumentBase(BaseModel):
    """Base document fields."""
    
    title: str = Field(min_length=3, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    document_type: DocumentType
    
    @field_validator("title")
    @classmethod
    def sanitize_title(cls, v: str) -> str:
        v = re.sub(r'[<>"\';\\]', '', v)
        return v.strip()


class DocumentCreate(DocumentBase):
    """Schema for uploading a new document."""
    
    # Dates
    effective_date: Optional[date] = None
    review_date: Optional[date] = None
    expiration_date: Optional[date] = None
    
    # For screenshots
    captured_at: Optional[datetime] = None
    
    # Compliance mapping
    controls: Optional[List[str]] = Field(
        default=None,
        description="Control IDs this document provides evidence for (e.g., ['AC-1', 'PL-1'])"
    )
    
    # Scope
    system_id: Optional[int] = Field(
        default=None,
        description="System ID if document is scoped to a specific system"
    )
    
    # Access control
    visibility: DocumentVisibility = DocumentVisibility.INTERNAL
    share_with_auditors: bool = True


class DocumentUpdate(BaseModel):
    """Schema for updating document metadata."""
    
    title: Optional[str] = Field(default=None, min_length=3, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[DocumentStatus] = None
    
    effective_date: Optional[date] = None
    review_date: Optional[date] = None
    expiration_date: Optional[date] = None
    
    controls: Optional[List[str]] = None
    visibility: Optional[DocumentVisibility] = None
    share_with_auditors: Optional[bool] = None


class DocumentResponse(BaseModel):
    """Schema for document response."""
    
    id: int
    title: str
    description: Optional[str] = None
    
    # File info
    file_name: str
    file_type: str
    file_size_bytes: int
    
    # Classification
    document_type: DocumentType
    status: DocumentStatus
    
    # Dates
    effective_date: Optional[date] = None
    review_date: Optional[date] = None
    expiration_date: Optional[date] = None
    captured_at: Optional[datetime] = None
    
    # Compliance
    controls: List[str] = Field(default_factory=list)
    
    # Scope
    system_id: Optional[int] = None
    system_name: Optional[str] = None
    
    # Access
    visibility: DocumentVisibility
    share_with_auditors: bool
    
    # Version
    version: str
    has_previous_version: bool = False
    
    # Ownership
    uploaded_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
    
    # Status helpers
    is_expired: bool = False
    needs_review: bool = False
    
    class Config:
        from_attributes = True


class DocumentListResponse(BaseModel):
    """Paginated document list."""
    
    items: List[DocumentResponse]
    total: int
    page: int
    per_page: int
    pages: int


class DocumentUploadResponse(BaseModel):
    """Response after successful document upload."""
    
    id: int
    title: str
    file_name: str
    file_size_bytes: int
    status: DocumentStatus
    message: str = "Document uploaded successfully"


# Evidence Request Schemas

class EvidenceRequestCreate(BaseModel):
    """Schema for creating an evidence request."""
    
    audit_name: str = Field(min_length=3, max_length=255)
    control_id: str = Field(min_length=2, max_length=50)
    description: str = Field(min_length=10, max_length=2000)
    priority: str = Field(default="medium", pattern="^(high|medium|low)$")
    due_date: date
    assigned_to_id: Optional[int] = None


class EvidenceRequestUpdate(BaseModel):
    """Schema for updating an evidence request."""
    
    assigned_to_id: Optional[int] = None
    status: Optional[str] = None
    response_notes: Optional[str] = Field(default=None, max_length=2000)
    review_notes: Optional[str] = Field(default=None, max_length=2000)


class EvidenceRequestResponse(BaseModel):
    """Schema for evidence request response."""
    
    id: int
    audit_name: str
    control_id: str
    description: str
    priority: str
    due_date: date
    
    # Requester
    requested_by: str
    requested_at: datetime
    
    # Assignment
    assigned_to: Optional[str] = None
    
    # Status
    status: str
    is_overdue: bool = False
    
    # Response
    response_notes: Optional[str] = None
    documents_provided: List[int] = Field(default_factory=list)
    responded_at: Optional[datetime] = None
    
    # Review
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class EvidenceRequestListResponse(BaseModel):
    """Paginated evidence request list."""
    
    items: List[EvidenceRequestResponse]
    total: int
    page: int
    per_page: int
    pages: int


class EvidencePackageRequest(BaseModel):
    """Request to generate an evidence package for audit."""
    
    audit_name: str = Field(min_length=3, max_length=255)
    
    # What to include
    include_automated_evidence: bool = True
    include_documents: bool = True
    document_types: Optional[List[DocumentType]] = None
    
    # Scope
    system_ids: Optional[List[int]] = None
    framework_ids: Optional[List[int]] = None
    control_ids: Optional[List[str]] = None
    
    # Time range
    from_date: Optional[date] = None
    to_date: Optional[date] = None
    
    # Output format
    format: str = Field(default="zip", pattern="^(zip|tar)$")


class EvidencePackageResponse(BaseModel):
    """Response with evidence package info."""
    
    package_id: str
    audit_name: str
    file_name: str
    file_size_bytes: int
    document_count: int
    download_url: str
    expires_at: datetime
    created_at: datetime

