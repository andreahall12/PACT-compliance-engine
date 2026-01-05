"""
Policy and Framework models.

Manages:
- Compliance frameworks (NIST, PCI-DSS, ISO 27001, etc.)
- Custom SHACL policies
- Framework mappings and cross-walks
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, List
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey, Enum, Text, Integer
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.system import system_frameworks


class FrameworkStatus(str, PyEnum):
    """Status of a framework in the organization."""
    ACTIVE = "active"          # Actively enforced
    AVAILABLE = "available"    # Available but not enabled
    DEPRECATED = "deprecated"  # No longer supported


class PolicyStatus(str, PyEnum):
    """Status of a custom policy."""
    DRAFT = "draft"
    ACTIVE = "active"
    TESTING = "testing"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class PolicyFramework(Base):
    """
    Compliance framework definition (e.g., NIST 800-53, PCI-DSS 4.0).
    
    Frameworks can be:
    - Built-in (shipped with PACT)
    - Imported from OSCAL catalogs
    - Custom (organization-specific)
    """
    
    __tablename__ = "policy_frameworks"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    framework_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Source
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    oscal_catalog_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    oscal_profile_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Status
    status: Mapped[FrameworkStatus] = mapped_column(
        Enum(FrameworkStatus),
        default=FrameworkStatus.AVAILABLE
    )
    
    # Control count (cached for performance)
    control_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # SHACL rules file path (relative to policies directory)
    shacl_rules_file: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Cross-walk mappings to other frameworks (JSON)
    # {"PCI-DSS 4.0": {"AC-3": ["Req 7.1", "Req 7.2"]}}
    cross_walk_mappings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Metadata
    publisher: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    publication_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
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
    
    # Who enabled/configured this
    enabled_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Relationships
    enabled_by: Mapped[Optional["User"]] = relationship("User")
    systems: Mapped[List["System"]] = relationship(
        "System",
        secondary=system_frameworks,
        back_populates="frameworks"
    )
    custom_policies: Mapped[List["CustomPolicy"]] = relationship(
        "CustomPolicy",
        back_populates="framework"
    )
    
    def __repr__(self) -> str:
        return f"<PolicyFramework {self.framework_id} v{self.version}>"
    
    def get_cross_walk_mappings(self) -> dict:
        """Parse cross-walk mappings from JSON."""
        import json
        if not self.cross_walk_mappings:
            return {}
        try:
            return json.loads(self.cross_walk_mappings)
        except json.JSONDecodeError:
            return {}


class CustomPolicy(Base):
    """
    Custom SHACL policy rule created by Compliance Officers.
    
    Can be:
    - Created via natural language (Gemara integration)
    - Written directly in SHACL
    - Extensions to existing framework controls
    """
    
    __tablename__ = "custom_policies"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    policy_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Classification
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # critical, high, medium, low
    status: Mapped[PolicyStatus] = mapped_column(
        Enum(PolicyStatus),
        default=PolicyStatus.DRAFT
    )
    
    # Associated framework (optional - can be standalone)
    framework_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("policy_frameworks.id", ondelete="SET NULL"),
        nullable=True
    )
    control_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g., "AC-3"
    
    # The actual SHACL rule
    shacl_rule: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Original natural language (if created via Gemara)
    natural_language_source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Ownership
    created_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    approved_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Testing
    test_results: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    last_tested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
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
    framework: Mapped[Optional["PolicyFramework"]] = relationship(
        "PolicyFramework",
        back_populates="custom_policies"
    )
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])
    approved_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[approved_by_id])
    
    def __repr__(self) -> str:
        return f"<CustomPolicy {self.policy_id}>"
    
    def can_activate(self) -> bool:
        """Check if policy is ready to be activated."""
        return (
            self.shacl_rule and
            len(self.shacl_rule.strip()) > 0 and
            self.approved_by_id is not None
        )


# Import for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.user import User
    from app.models.system import System

