"""
Incident and Near-Miss schemas.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import re

from app.models.incident import IncidentType, IncidentSeverity, IncidentStatus


class IncidentBase(BaseModel):
    """Base incident fields."""
    
    title: str = Field(min_length=5, max_length=255)
    description: str = Field(min_length=20, max_length=5000)
    incident_type: IncidentType
    severity: IncidentSeverity
    
    @field_validator("title")
    @classmethod
    def sanitize_title(cls, v: str) -> str:
        v = re.sub(r'[<>"\';\\]', '', v)
        return v.strip()


class IncidentCreate(IncidentBase):
    """Schema for creating a new incident."""
    
    occurred_at: datetime
    detected_at: datetime
    
    # Affected systems
    primary_system_id: Optional[int] = None
    affected_system_ids: Optional[List[int]] = None
    
    # Attack details
    attack_vector: Optional[str] = Field(default=None, max_length=255)


class IncidentUpdate(BaseModel):
    """Schema for updating an incident."""
    
    title: Optional[str] = Field(default=None, min_length=5, max_length=255)
    description: Optional[str] = Field(default=None, min_length=20, max_length=5000)
    status: Optional[IncidentStatus] = None
    
    # Timeline updates
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Analysis
    root_cause: Optional[str] = Field(default=None, max_length=2000)
    attack_vector: Optional[str] = Field(default=None, max_length=255)
    lessons_learned: Optional[str] = Field(default=None, max_length=5000)
    
    # Control correlation
    controls_that_would_have_prevented: Optional[List[str]] = None
    controls_that_detected: Optional[List[str]] = None
    
    # Data impact
    data_affected: Optional[List[str]] = None
    records_affected_count: Optional[int] = None


class IncidentResponse(BaseModel):
    """Schema for incident response."""
    
    id: int
    incident_id: str
    title: str
    description: str
    
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    
    # Timeline
    occurred_at: datetime
    detected_at: datetime
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Computed metrics
    time_to_detect_hours: Optional[float] = None
    time_to_contain_hours: Optional[float] = None
    
    # Affected systems
    primary_system: Optional[str] = None
    affected_systems: List[str] = Field(default_factory=list)
    
    # Analysis
    root_cause: Optional[str] = None
    attack_vector: Optional[str] = None
    lessons_learned: Optional[str] = None
    
    # Compliance correlation
    had_compliance_gap: bool = False
    non_compliant_controls: List[str] = Field(default_factory=list)
    controls_that_would_have_prevented: List[str] = Field(default_factory=list)
    controls_that_detected: List[str] = Field(default_factory=list)
    
    # Data impact
    data_affected: List[str] = Field(default_factory=list)
    records_affected_count: Optional[int] = None
    
    # Ownership
    reported_by: Optional[str] = None
    lead_investigator: Optional[str] = None
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class IncidentListResponse(BaseModel):
    """Paginated incident list."""
    
    items: List[IncidentResponse]
    total: int
    page: int
    per_page: int
    pages: int


class NearMissCreate(BaseModel):
    """Schema for recording a near-miss."""
    
    title: str = Field(min_length=5, max_length=255)
    description: str = Field(min_length=20, max_length=5000)
    
    would_have_been_type: IncidentType
    would_have_been_severity: IncidentSeverity
    
    occurred_at: datetime
    target_system_id: Optional[int] = None
    
    # What stopped it
    blocking_controls: Optional[List[str]] = None
    detection_controls: Optional[List[str]] = None
    
    attack_vector: Optional[str] = Field(default=None, max_length=255)
    attack_details: Optional[str] = Field(default=None, max_length=2000)


class NearMissResponse(BaseModel):
    """Schema for near-miss response."""
    
    id: int
    near_miss_id: str
    title: str
    description: str
    
    would_have_been_type: IncidentType
    would_have_been_severity: IncidentSeverity
    
    occurred_at: datetime
    target_system: Optional[str] = None
    
    blocking_controls: List[str] = Field(default_factory=list)
    detection_controls: List[str] = Field(default_factory=list)
    
    attack_vector: Optional[str] = None
    attack_details: Optional[str] = None
    
    reported_by: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


# Research/Analytics schemas

class ComplianceSecurityCorrelation(BaseModel):
    """Statistics for compliance-security correlation research."""
    
    # Overall stats
    total_incidents: int
    incidents_with_compliance_gap: int
    incidents_without_gap: int
    gap_percentage: float
    
    # Near misses (controls working)
    total_near_misses: int
    controls_that_blocked: dict  # Control ID -> count of blocks
    
    # Most impactful gaps
    top_failing_controls: List[dict]  # [{control_id, incident_count, severity_sum}]
    
    # Time series
    incidents_over_time: List[dict]  # [{month, incident_count, gap_count}]


class HistoricalComplianceState(BaseModel):
    """Compliance state at a specific point in time."""
    
    as_of: datetime
    
    # Summary
    total_assessments: int
    pass_count: int
    fail_count: int
    compliance_rate: float
    
    # By system
    systems: List[dict]  # [{system_id, pass_count, fail_count}]
    
    # By framework
    frameworks: List[dict]  # [{framework_id, pass_count, fail_count}]
    
    # Specific failures
    failures: List[dict]  # [{system, control, asset, timestamp}]

