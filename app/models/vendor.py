"""
Vendor and Third-Party Risk models.

Tracks:
- Vendor information
- SOC 2 reports and attestations
- Risk assessments
"""

from datetime import datetime, timezone, date
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, Enum, Text, Integer, Date, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class VendorRisk(str, PyEnum):
    """Vendor risk classification."""
    CRITICAL = "critical"   # Mission-critical, high data access
    HIGH = "high"           # Important, sensitive data access
    MEDIUM = "medium"       # Standard vendor
    LOW = "low"             # Minimal risk


class VendorCategory(str, PyEnum):
    """Category of vendor service."""
    IAAS = "iaas"                    # Infrastructure (AWS, GCP, Azure)
    PAAS = "paas"                    # Platform services
    SAAS = "saas"                    # SaaS applications
    SECURITY = "security"            # Security tools
    PAYMENTS = "payments"            # Payment processors
    ANALYTICS = "analytics"          # Analytics/monitoring
    COMMUNICATIONS = "communications"  # Email, messaging
    HR = "hr"                        # HR systems
    OTHER = "other"


class AttestationStatus(str, PyEnum):
    """Status of vendor attestation (SOC 2, etc.)."""
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"  # Within 60 days
    EXPIRED = "expired"
    NOT_AVAILABLE = "not_available"
    PENDING = "pending"              # Requested but not received


class Vendor(Base):
    """
    Third-party vendor with risk tracking.
    
    Tracks SOC 2 reports, contracts, and risk assessments.
    """
    
    __tablename__ = "vendors"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    vendor_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    website: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Classification
    category: Mapped[VendorCategory] = mapped_column(Enum(VendorCategory), nullable=False)
    risk_level: Mapped[VendorRisk] = mapped_column(
        Enum(VendorRisk),
        default=VendorRisk.MEDIUM
    )
    
    # What data/access do they have?
    data_access: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: ["PII", "PCI"]
    system_access: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: system IDs
    
    # Contract info
    contract_start_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    contract_end_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    contract_document_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # SOC 2 / Attestation
    has_soc2: Mapped[bool] = mapped_column(Boolean, default=False)
    soc2_type: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # "Type I", "Type II"
    soc2_report_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    soc2_expiration_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    soc2_document_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Other attestations (JSON)
    # {"ISO_27001": {"status": "valid", "expires": "2025-12-31"}, ...}
    other_attestations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Risk assessment
    last_risk_assessment: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    next_risk_assessment: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    risk_assessment_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Contact
    primary_contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    primary_contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    security_contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Ownership
    owner_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
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
    owner: Mapped[Optional["User"]] = relationship("User")
    contract_document: Mapped[Optional["Document"]] = relationship(
        "Document",
        foreign_keys=[contract_document_id]
    )
    soc2_document: Mapped[Optional["Document"]] = relationship(
        "Document",
        foreign_keys=[soc2_document_id]
    )
    
    def __repr__(self) -> str:
        return f"<Vendor {self.name}>"
    
    def get_soc2_status(self) -> AttestationStatus:
        """Calculate current SOC 2 attestation status."""
        if not self.has_soc2:
            return AttestationStatus.NOT_AVAILABLE
        
        if not self.soc2_expiration_date:
            return AttestationStatus.PENDING
        
        today = date.today()
        if today > self.soc2_expiration_date:
            return AttestationStatus.EXPIRED
        
        from datetime import timedelta
        if today >= self.soc2_expiration_date - timedelta(days=60):
            return AttestationStatus.EXPIRING_SOON
        
        return AttestationStatus.VALID
    
    def needs_review(self) -> bool:
        """Check if vendor needs risk review."""
        if not self.next_risk_assessment:
            return True
        return date.today() >= self.next_risk_assessment


# Import for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.user import User
    from app.models.document import Document

