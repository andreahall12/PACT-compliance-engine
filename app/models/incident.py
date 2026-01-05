"""
Security Incident and Near-Miss models.

For tracking security events and correlating with compliance state.
Enables research into "Does compliance = security?"
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, List
from sqlalchemy import (
    String, DateTime, ForeignKey, Enum, Text, Integer, Table, Column
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class IncidentSeverity(str, PyEnum):
    """Severity classification for incidents."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentType(str, PyEnum):
    """Type of security incident."""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    MALWARE = "malware"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    MISCONFIGURATION = "misconfiguration"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    OTHER = "other"


class IncidentStatus(str, PyEnum):
    """Status of incident investigation."""
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    POST_MORTEM = "post_mortem"
    CLOSED = "closed"


# Association table for incident-affected systems
incident_systems = Table(
    "incident_systems",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("security_incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("system_id", Integer, ForeignKey("systems.id", ondelete="CASCADE"), primary_key=True),
)


class SecurityIncident(Base):
    """
    Security incident record with compliance correlation.
    
    Key feature: Stores compliance state at time of incident
    to enable research into compliance effectiveness.
    """
    
    __tablename__ = "security_incidents"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    incident_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Classification
    incident_type: Mapped[IncidentType] = mapped_column(Enum(IncidentType), nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus),
        default=IncidentStatus.DETECTED
    )
    
    # Timeline
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Primary affected system
    primary_system_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Root cause analysis
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attack_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # CVE ID, phishing, etc.
    
    # Compliance correlation (CRITICAL for research)
    # JSON: {"AC-3": "PASS", "CM-7": "FAIL", ...}
    compliance_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # JSON array of control IDs that were failing
    non_compliant_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Analysis
    controls_that_would_have_prevented: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    controls_that_detected: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Data impact
    data_affected: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: ["PII", "PCI"]
    records_affected_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Reporting
    reported_to_regulators: Mapped[Optional[bool]] = mapped_column(default=False)
    regulator_report_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Ownership
    reported_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    lead_investigator_id: Mapped[Optional[int]] = mapped_column(
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
    
    # Relationships
    primary_system: Mapped[Optional["System"]] = relationship("System", back_populates="incidents")
    affected_systems: Mapped[List["System"]] = relationship(
        "System",
        secondary=incident_systems,
    )
    reported_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[reported_by_id])
    lead_investigator: Mapped[Optional["User"]] = relationship("User", foreign_keys=[lead_investigator_id])
    
    def __repr__(self) -> str:
        return f"<SecurityIncident {self.incident_id}>"
    
    def get_non_compliant_controls(self) -> list[str]:
        """Parse non-compliant controls from JSON."""
        import json
        if not self.non_compliant_controls:
            return []
        try:
            return json.loads(self.non_compliant_controls)
        except json.JSONDecodeError:
            return []
    
    def had_compliance_gap(self) -> bool:
        """Check if there was a compliance gap at time of incident."""
        return len(self.get_non_compliant_controls()) > 0
    
    def time_to_detect(self) -> Optional[float]:
        """Calculate detection time in hours."""
        if not self.detected_at or not self.occurred_at:
            return None
        delta = self.detected_at - self.occurred_at
        return delta.total_seconds() / 3600
    
    def time_to_contain(self) -> Optional[float]:
        """Calculate containment time in hours from detection."""
        if not self.contained_at or not self.detected_at:
            return None
        delta = self.contained_at - self.detected_at
        return delta.total_seconds() / 3600


class NearMiss(Base):
    """
    Near-miss: Attack that was blocked or detected before causing harm.
    
    Critical for proving control effectiveness - these are the successes.
    """
    
    __tablename__ = "near_misses"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Identification
    near_miss_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # What would have happened
    would_have_been_type: Mapped[IncidentType] = mapped_column(Enum(IncidentType), nullable=False)
    would_have_been_severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), nullable=False)
    
    # When/where
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    target_system_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("systems.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # How it was stopped (CRITICAL for proving control value)
    blocking_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    detection_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    
    # What was attempted
    attack_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    attack_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Ownership
    reported_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    
    # Relationships
    target_system: Mapped[Optional["System"]] = relationship("System")
    reported_by: Mapped[Optional["User"]] = relationship("User")
    
    def __repr__(self) -> str:
        return f"<NearMiss {self.near_miss_id}>"
    
    def get_blocking_controls(self) -> list[str]:
        """Parse blocking controls from JSON."""
        import json
        if not self.blocking_controls:
            return []
        try:
            return json.loads(self.blocking_controls)
        except json.JSONDecodeError:
            return []


# Import for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.user import User
    from app.models.system import System

