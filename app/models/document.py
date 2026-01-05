"""
Document and Evidence models.

Handles:
- Policy documents, procedures, screenshots
- Version control and expiration tracking
- Evidence request workflow for auditors
"""

from datetime import datetime, timezone, date
from enum import Enum as PyEnum
from typing import Optional, List
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey, Enum, Text, Integer, Date
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DocumentType(str, PyEnum):
    """Types of documentary evidence."""
    POLICY = "policy"
    PROCEDURE = "procedure"
    SCREENSHOT = "screenshot"
    TRAINING_RECORD = "training_record"
    ATTESTATION = "attestation"          # Vendor SOC 2, pen test reports
    AUDIT_EVIDENCE = "audit_evidence"    # Access reviews, exports
    CONTRACT = "contract"                # NDAs, BAAs, DPAs
    MEETING_MINUTES = "meeting_minutes"
    OTHER = "other"


class DocumentStatus(str, PyEnum):
    """Document lifecycle status."""
    DRAFT = "draft"
    PUBLISHED = "published"
    UNDER_REVIEW = "under_review"
    EXPIRED = "expired"
    ARCHIVED = "archived"


class DocumentVisibility(str, PyEnum):
    """Who can access the document."""
    INTERNAL = "internal"          # All internal users
    TEAM_ONLY = "team_only"        # Specific teams only
    AUDIT_SHARED = "audit_shared"  # Shared with external auditors


class EvidenceRequestStatus(str, PyEnum):
    """Status of an evidence request from auditors."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EvidenceRequestPriority(str, PyEnum):
    """Priority level for evidence requests."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Document(Base):
    """
    Evidence document with version control and access management.
    
    Security:
    - File hash stored for integrity verification
    - Access controlled by visibility settings
    - Audit trail for all access
    """
    
    __tablename__ = "documents"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # File information
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_type: Mapped[str] = mapped_column(String(50), nullable=False)  # pdf, docx, png, etc.
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    
    # Classification
    document_type: Mapped[DocumentType] = mapped_column(Enum(DocumentType), nullable=False)
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(DocumentStatus),
        default=DocumentStatus.DRAFT
    )
    
    # Dates
    effective_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    review_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    expiration_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    
    # For screenshots: when was this captured?
    captured_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Compliance mapping (JSON arrays)
    controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # ["AC-1", "PL-1"]
    frameworks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Auto-derived
    
    # Scope to specific system (optional)
    system_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Access control
    visibility: Mapped[DocumentVisibility] = mapped_column(
        Enum(DocumentVisibility),
        default=DocumentVisibility.INTERNAL
    )
    teams_allowed: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of team IDs
    share_with_auditors: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Versioning
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    previous_version_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Ownership
    uploaded_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    approved_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    
    # Soft delete
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    system: Mapped[Optional["System"]] = relationship("System", back_populates="documents")
    uploaded_by: Mapped["User"] = relationship("User", foreign_keys=[uploaded_by_id])
    approved_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[approved_by_id])
    previous_version: Mapped[Optional["Document"]] = relationship("Document", remote_side=[id])
    
    def __repr__(self) -> str:
        return f"<Document {self.title} v{self.version}>"
    
    def get_controls(self) -> list[str]:
        """Parse controls from JSON storage."""
        import json
        if not self.controls:
            return []
        try:
            return json.loads(self.controls)
        except json.JSONDecodeError:
            return []
    
    def set_controls(self, controls: list[str]) -> None:
        """Store controls as JSON."""
        import json
        self.controls = json.dumps(controls)
    
    def is_expired(self) -> bool:
        """Check if document has expired."""
        if not self.expiration_date:
            return False
        return date.today() > self.expiration_date
    
    def needs_review(self) -> bool:
        """Check if document needs review (within 30 days of review date)."""
        if not self.review_date:
            return False
        from datetime import timedelta
        review_threshold = self.review_date - timedelta(days=30)
        return date.today() >= review_threshold


class EvidenceRequest(Base):
    """
    Request from auditors for specific evidence.
    
    Workflow:
    1. Auditor creates request with description and due date
    2. Assigned to internal user
    3. User uploads document(s) as response
    4. Auditor marks as reviewed
    """
    
    __tablename__ = "evidence_requests"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Context
    audit_name: Mapped[str] = mapped_column(String(255), nullable=False)  # "SOC 2 Type II 2025"
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)   # "AC-2"
    
    # Request details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[EvidenceRequestPriority] = mapped_column(
        Enum(EvidenceRequestPriority),
        default=EvidenceRequestPriority.MEDIUM
    )
    due_date: Mapped[date] = mapped_column(Date, nullable=False)
    
    # Requester (auditor)
    requested_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    
    # Assignment
    assigned_to_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Response
    status: Mapped[EvidenceRequestStatus] = mapped_column(
        Enum(EvidenceRequestStatus),
        default=EvidenceRequestStatus.PENDING
    )
    response_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    documents_provided: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of doc IDs
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Auditor review
    reviewed_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    review_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    
    # Relationships
    requested_by: Mapped["User"] = relationship("User", foreign_keys=[requested_by_id])
    assigned_to: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_to_id])
    reviewed_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[reviewed_by_id])
    
    def __repr__(self) -> str:
        return f"<EvidenceRequest {self.control_id} for {self.audit_name}>"
    
    def is_overdue(self) -> bool:
        """Check if request is past due date."""
        return date.today() > self.due_date and self.status in {
            EvidenceRequestStatus.PENDING,
            EvidenceRequestStatus.IN_PROGRESS
        }


# Import for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.user import User
    from app.models.system import System

