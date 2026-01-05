"""
System, Product, and Business Process models.

Represents the organizational hierarchy:
- Products contain Systems
- Systems support Business Processes
- Systems have a lifecycle (planned → active → deprecated → archived)
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, List
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey, Enum, Text, Table, Column, Integer, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class SystemStatus(str, PyEnum):
    """Lifecycle status for systems."""
    PLANNED = "planned"         # Registered but not yet deployed
    ACTIVE = "active"           # In production, being monitored
    DEPRECATED = "deprecated"   # Scheduled for EOL
    ARCHIVED = "archived"       # Historical record only


class DataClassification(str, PyEnum):
    """Data sensitivity classification."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"           # Personally Identifiable Information
    PCI = "pci"           # Payment Card Industry
    PHI = "phi"           # Protected Health Information


class Criticality(str, PyEnum):
    """Business criticality level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Environment(str, PyEnum):
    """Deployment environment."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


# Association table for system-framework applicability
system_frameworks = Table(
    "system_frameworks",
    Base.metadata,
    Column("system_id", Integer, ForeignKey("systems.id", ondelete="CASCADE"), primary_key=True),
    Column("framework_id", Integer, ForeignKey("policy_frameworks.id", ondelete="CASCADE"), primary_key=True),
)

# Association table for system-process support
system_processes = Table(
    "system_processes",
    Base.metadata,
    Column("system_id", Integer, ForeignKey("systems.id", ondelete="CASCADE"), primary_key=True),
    Column("process_id", Integer, ForeignKey("business_processes.id", ondelete="CASCADE"), primary_key=True),
)

# Association table for product-system membership
product_systems = Table(
    "product_systems",
    Base.metadata,
    Column("product_id", Integer, ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
    Column("system_id", Integer, ForeignKey("systems.id", ondelete="CASCADE"), primary_key=True),
)


class BusinessProcess(Base):
    """
    Business process that systems support.
    E.g., "Payment Processing", "Employee Onboarding"
    """
    
    __tablename__ = "business_processes"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Classification
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality),
        default=Criticality.MEDIUM
    )
    
    # Owner
    owner_team_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"),
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
    
    # Relationships
    owner_team: Mapped[Optional["Team"]] = relationship("Team")
    systems: Mapped[List["System"]] = relationship(
        "System",
        secondary=system_processes,
        back_populates="business_processes"
    )
    
    def __repr__(self) -> str:
        return f"<BusinessProcess {self.name}>"


class System(Base):
    """
    Information System with full lifecycle management.
    
    Represents a logical grouping of technical assets
    (e.g., "Payment Gateway Cluster", "HR Portal").
    """
    
    __tablename__ = "systems"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    system_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Lifecycle
    status: Mapped[SystemStatus] = mapped_column(
        Enum(SystemStatus),
        default=SystemStatus.ACTIVE,
        index=True
    )
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment),
        default=Environment.PRODUCTION
    )
    
    # Classification
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality),
        default=Criticality.MEDIUM
    )
    data_classifications: Mapped[Optional[str]] = mapped_column(
        Text,  # JSON array of DataClassification values
        nullable=True
    )
    
    # Ownership
    owner_team_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"),
        nullable=True
    )
    owner_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    backup_owner_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Integration
    ingest_source: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    sbom_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cmdb_link: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Deprecation info
    deprecation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    replacement_system_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True
    )
    scheduled_archive_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    created_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    deprecated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Soft delete
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    owner_team: Mapped[Optional["Team"]] = relationship("Team", foreign_keys=[owner_team_id])
    owner_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[owner_user_id])
    backup_owner: Mapped[Optional["User"]] = relationship("User", foreign_keys=[backup_owner_id])
    created_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by_id])
    replacement_system: Mapped[Optional["System"]] = relationship("System", remote_side=[id])
    
    business_processes: Mapped[List["BusinessProcess"]] = relationship(
        "BusinessProcess",
        secondary=system_processes,
        back_populates="systems"
    )
    
    frameworks: Mapped[List["PolicyFramework"]] = relationship(
        "PolicyFramework",
        secondary=system_frameworks,
        back_populates="systems"
    )
    
    products: Mapped[List["Product"]] = relationship(
        "Product",
        secondary=product_systems,
        back_populates="systems"
    )
    
    documents: Mapped[List["Document"]] = relationship("Document", back_populates="system")
    incidents: Mapped[List["SecurityIncident"]] = relationship("SecurityIncident", back_populates="primary_system")
    
    def __repr__(self) -> str:
        return f"<System {self.system_id}>"
    
    def deprecate(self, reason: str, replacement_id: Optional[int] = None) -> None:
        """Mark system as deprecated."""
        self.status = SystemStatus.DEPRECATED
        self.deprecated_at = datetime.now(timezone.utc)
        self.deprecation_reason = reason
        self.replacement_system_id = replacement_id
    
    def archive(self) -> None:
        """Archive the system (soft delete with historical preservation)."""
        self.status = SystemStatus.ARCHIVED
        self.archived_at = datetime.now(timezone.utc)
    
    def get_data_classifications(self) -> list[DataClassification]:
        """Parse data classifications from JSON storage."""
        import json
        if not self.data_classifications:
            return []
        try:
            return [DataClassification(c) for c in json.loads(self.data_classifications)]
        except (json.JSONDecodeError, ValueError):
            return []
    
    def set_data_classifications(self, classifications: list[DataClassification]) -> None:
        """Store data classifications as JSON."""
        import json
        self.data_classifications = json.dumps([c.value for c in classifications])


class Product(Base):
    """
    Product that contains multiple systems.
    For software companies tracking certifications per product.
    """
    
    __tablename__ = "products"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    product_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Ownership
    owner_team_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"),
        nullable=True
    )
    product_manager_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Certifications (JSON: {"SOC2": {"status": "certified", "expires": "2025-12-31"}, ...})
    certifications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
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
    owner_team: Mapped[Optional["Team"]] = relationship("Team")
    product_manager: Mapped[Optional["User"]] = relationship("User")
    
    systems: Mapped[List["System"]] = relationship(
        "System",
        secondary=product_systems,
        back_populates="products"
    )
    
    def __repr__(self) -> str:
        return f"<Product {self.product_id}>"
    
    def get_certifications(self) -> dict:
        """Parse certifications from JSON storage."""
        import json
        if not self.certifications:
            return {}
        try:
            return json.loads(self.certifications)
        except json.JSONDecodeError:
            return {}
    
    def set_certification(self, framework: str, status: str, expires: Optional[str] = None) -> None:
        """Update a certification status."""
        import json
        certs = self.get_certifications()
        certs[framework] = {"status": status, "expires": expires}
        self.certifications = json.dumps(certs)


# Import for type hints (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.user import User, Team
    from app.models.policy import PolicyFramework
    from app.models.document import Document
    from app.models.incident import SecurityIncident

