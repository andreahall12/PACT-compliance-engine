"""
Audit logging model for security and compliance.

Every significant action is logged for:
- Security monitoring
- Compliance evidence (who did what, when)
- Forensic investigation
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, Enum, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AuditAction(str, PyEnum):
    """Categories of auditable actions."""
    # Authentication
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    API_TOKEN_GENERATED = "api_token_generated"
    API_TOKEN_REVOKED = "api_token_revoked"
    
    # User management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    
    # System management
    SYSTEM_CREATED = "system_created"
    SYSTEM_UPDATED = "system_updated"
    SYSTEM_DEPRECATED = "system_deprecated"
    SYSTEM_ARCHIVED = "system_archived"
    SYSTEM_DELETED = "system_deleted"
    
    # Product management
    PRODUCT_CREATED = "product_created"
    PRODUCT_UPDATED = "product_updated"
    PRODUCT_DELETED = "product_deleted"
    
    # Document management
    DOCUMENT_UPLOADED = "document_uploaded"
    DOCUMENT_UPDATED = "document_updated"
    DOCUMENT_DELETED = "document_deleted"
    DOCUMENT_DOWNLOADED = "document_downloaded"
    DOCUMENT_APPROVED = "document_approved"
    
    # Evidence requests
    EVIDENCE_REQUESTED = "evidence_requested"
    EVIDENCE_SUBMITTED = "evidence_submitted"
    EVIDENCE_REVIEWED = "evidence_reviewed"
    
    # Policy management
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_DELETED = "policy_deleted"
    FRAMEWORK_ENABLED = "framework_enabled"
    FRAMEWORK_DISABLED = "framework_disabled"
    
    # Compliance operations
    SCAN_EXECUTED = "scan_executed"
    REPORT_GENERATED = "report_generated"
    EXCEPTION_CREATED = "exception_created"
    EXCEPTION_APPROVED = "exception_approved"
    EXCEPTION_REJECTED = "exception_rejected"
    
    # Incidents
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_CLOSED = "incident_closed"
    
    # Settings
    SETTINGS_UPDATED = "settings_updated"
    INTEGRATION_CONFIGURED = "integration_configured"
    
    # Data access (for sensitive data audit)
    SENSITIVE_DATA_ACCESSED = "sensitive_data_accessed"
    BULK_EXPORT = "bulk_export"


class AuditLog(Base):
    """
    Immutable audit log entry.
    
    Security considerations:
    - Records are append-only (no updates/deletes in normal operation)
    - IP address and user agent captured for forensics
    - Timestamps are UTC
    """
    
    __tablename__ = "audit_logs"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # When
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    
    # Who (can be null for system actions or failed auth)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Preserved even if user deleted
    
    # What
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False, index=True)
    
    # Resource affected
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # user, system, document, etc.
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Human-readable identifier
    
    # Details (JSON for flexibility)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Outcome
    success: Mapped[bool] = mapped_column(default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Context for forensics
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 max length
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # Correlation ID
    
    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")
    
    def __repr__(self) -> str:
        return f"<AuditLog {self.action.value} by {self.user_email} at {self.timestamp}>"
    
    @classmethod
    def create(
        cls,
        action: AuditAction,
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        details: Optional[dict] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> "AuditLog":
        """Factory method to create audit log entries."""
        import json
        
        return cls(
            action=action,
            user_id=user_id,
            user_email=user_email,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            resource_name=resource_name,
            details=json.dumps(details) if details else None,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )


# Import for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.user import User

