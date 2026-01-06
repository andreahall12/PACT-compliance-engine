"""
Incident and Near-Miss management endpoints.

Key feature: Correlates security incidents with compliance state
to help prove/disprove "Compliance = Security".
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.user import User
from app.models.system import System
from app.models.incident import (
    SecurityIncident, NearMiss, IncidentType, IncidentSeverity, IncidentStatus
)
from app.models.audit import AuditLog, AuditAction
from app.auth.dependencies import (
    get_current_user,
    require_permission,
    get_client_ip,
    get_user_agent,
)
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    NearMissCreate,
    NearMissResponse,
    ComplianceSecurityCorrelation,
)
from app.schemas.common import PaginatedResponse

router = APIRouter()


def generate_incident_id() -> str:
    """Generate unique incident ID."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_suffix = secrets.token_hex(3).upper()
    return f"INC-{timestamp}-{random_suffix}"


def generate_near_miss_id() -> str:
    """Generate unique near-miss ID."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_suffix = secrets.token_hex(3).upper()
    return f"NM-{timestamp}-{random_suffix}"


# =============================================================================
# Incident CRUD
# =============================================================================

@router.get("", response_model=PaginatedResponse[IncidentResponse])
async def list_incidents(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    severity: Optional[IncidentSeverity] = None,
    incident_type: Optional[IncidentType] = None,
    system_id: Optional[int] = None,
    has_compliance_gap: Optional[bool] = None,
    current_user: User = Depends(require_permission("incidents.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    List security incidents with filtering.
    
    Key filter: has_compliance_gap - find incidents that occurred
    while a related control was failing.
    """
    query = select(SecurityIncident)
    count_query = select(func.count(SecurityIncident.id))
    
    if status_filter:
        query = query.where(SecurityIncident.status == status_filter)
        count_query = count_query.where(SecurityIncident.status == status_filter)
    
    if severity:
        query = query.where(SecurityIncident.severity == severity)
        count_query = count_query.where(SecurityIncident.severity == severity)
    
    if incident_type:
        query = query.where(SecurityIncident.incident_type == incident_type)
        count_query = count_query.where(SecurityIncident.incident_type == incident_type)
    
    if system_id:
        query = query.where(SecurityIncident.primary_system_id == system_id)
        count_query = count_query.where(SecurityIncident.primary_system_id == system_id)
    
    if has_compliance_gap is not None:
        if has_compliance_gap:
            query = query.where(SecurityIncident.non_compliant_controls.isnot(None))
            count_query = count_query.where(SecurityIncident.non_compliant_controls.isnot(None))
        else:
            query = query.where(SecurityIncident.non_compliant_controls.is_(None))
            count_query = count_query.where(SecurityIncident.non_compliant_controls.is_(None))
    
    # Get total
    result = await db.execute(count_query)
    total = result.scalar()
    
    # Apply pagination
    offset = (page - 1) * per_page
    query = (
        query
        .options(
            selectinload(SecurityIncident.primary_system),
            selectinload(SecurityIncident.reported_by),
            selectinload(SecurityIncident.lead_investigator),
        )
        .offset(offset)
        .limit(per_page)
        .order_by(SecurityIncident.occurred_at.desc())
    )
    
    result = await db.execute(query)
    incidents = result.scalars().all()
    
    items = [
        IncidentResponse(
            id=i.id,
            incident_id=i.incident_id,
            title=i.title,
            description=i.description,
            incident_type=i.incident_type,
            severity=i.severity,
            status=i.status,
            occurred_at=i.occurred_at,
            detected_at=i.detected_at,
            contained_at=i.contained_at,
            resolved_at=i.resolved_at,
            time_to_detect_hours=i.time_to_detect(),
            time_to_contain_hours=i.time_to_contain(),
            primary_system=i.primary_system.display_name if i.primary_system else None,
            root_cause=i.root_cause,
            attack_vector=i.attack_vector,
            lessons_learned=i.lessons_learned,
            had_compliance_gap=i.had_compliance_gap(),
            non_compliant_controls=i.get_non_compliant_controls(),
            reported_by=i.reported_by.email if i.reported_by else None,
            lead_investigator=i.lead_investigator.email if i.lead_investigator else None,
            created_at=i.created_at,
            updated_at=i.updated_at,
        )
        for i in incidents
    ]
    
    return PaginatedResponse.create(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    request: Request,
    incident_data: IncidentCreate,
    current_user: User = Depends(require_permission("incidents.create")),
    db: AsyncSession = Depends(get_db),
):
    """
    Record a new security incident.
    
    On creation, we automatically capture the current compliance state
    of affected systems to enable correlation analysis.
    """
    incident = SecurityIncident(
        incident_id=generate_incident_id(),
        title=incident_data.title,
        description=incident_data.description,
        incident_type=incident_data.incident_type,
        severity=incident_data.severity,
        status=IncidentStatus.DETECTED,
        occurred_at=incident_data.occurred_at,
        detected_at=incident_data.detected_at,
        primary_system_id=incident_data.primary_system_id,
        attack_vector=incident_data.attack_vector,
        reported_by_id=current_user.id,
    )
    
    # TODO: Query knowledge graph for compliance state and store snapshot
    # This enables the "compliance = security" research
    
    db.add(incident)
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.INCIDENT_CREATED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="incident",
        resource_id=incident.incident_id,
        resource_name=incident.title,
        details={"severity": incident.severity.value},
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(incident)
    
    return IncidentResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        incident_type=incident.incident_type,
        severity=incident.severity,
        status=incident.status,
        occurred_at=incident.occurred_at,
        detected_at=incident.detected_at,
        reported_by=current_user.email,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: User = Depends(require_permission("incidents.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get incident details."""
    result = await db.execute(
        select(SecurityIncident)
        .where(SecurityIncident.incident_id == incident_id)
        .options(
            selectinload(SecurityIncident.primary_system),
            selectinload(SecurityIncident.affected_systems),
            selectinload(SecurityIncident.reported_by),
            selectinload(SecurityIncident.lead_investigator),
        )
    )
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    
    return IncidentResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        incident_type=incident.incident_type,
        severity=incident.severity,
        status=incident.status,
        occurred_at=incident.occurred_at,
        detected_at=incident.detected_at,
        contained_at=incident.contained_at,
        resolved_at=incident.resolved_at,
        time_to_detect_hours=incident.time_to_detect(),
        time_to_contain_hours=incident.time_to_contain(),
        primary_system=incident.primary_system.display_name if incident.primary_system else None,
        affected_systems=[s.display_name for s in incident.affected_systems],
        root_cause=incident.root_cause,
        attack_vector=incident.attack_vector,
        lessons_learned=incident.lessons_learned,
        had_compliance_gap=incident.had_compliance_gap(),
        non_compliant_controls=incident.get_non_compliant_controls(),
        reported_by=incident.reported_by.email if incident.reported_by else None,
        lead_investigator=incident.lead_investigator.email if incident.lead_investigator else None,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    request: Request,
    incident_id: str,
    incident_data: IncidentUpdate,
    current_user: User = Depends(require_permission("incidents.update")),
    db: AsyncSession = Depends(get_db),
):
    """Update incident details."""
    result = await db.execute(
        select(SecurityIncident).where(SecurityIncident.incident_id == incident_id)
    )
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    
    # Update fields
    if incident_data.title is not None:
        incident.title = incident_data.title
    if incident_data.description is not None:
        incident.description = incident_data.description
    if incident_data.status is not None:
        incident.status = incident_data.status
    if incident_data.contained_at is not None:
        incident.contained_at = incident_data.contained_at
    if incident_data.resolved_at is not None:
        incident.resolved_at = incident_data.resolved_at
    if incident_data.root_cause is not None:
        incident.root_cause = incident_data.root_cause
    if incident_data.attack_vector is not None:
        incident.attack_vector = incident_data.attack_vector
    if incident_data.lessons_learned is not None:
        incident.lessons_learned = incident_data.lessons_learned
    if incident_data.records_affected_count is not None:
        incident.records_affected_count = incident_data.records_affected_count
    
    # Store control correlations as JSON
    if incident_data.controls_that_would_have_prevented is not None:
        import json
        incident.controls_that_would_have_prevented = json.dumps(
            incident_data.controls_that_would_have_prevented
        )
    
    if incident_data.controls_that_detected is not None:
        import json
        incident.controls_that_detected = json.dumps(
            incident_data.controls_that_detected
        )
    
    # Audit log
    audit = AuditLog.create(
        action=AuditAction.INCIDENT_UPDATED,
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="incident",
        resource_id=incident.incident_id,
        resource_name=incident.title,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(incident)
    
    return IncidentResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        incident_type=incident.incident_type,
        severity=incident.severity,
        status=incident.status,
        occurred_at=incident.occurred_at,
        detected_at=incident.detected_at,
        contained_at=incident.contained_at,
        resolved_at=incident.resolved_at,
        root_cause=incident.root_cause,
        attack_vector=incident.attack_vector,
        lessons_learned=incident.lessons_learned,
        had_compliance_gap=incident.had_compliance_gap(),
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


# =============================================================================
# Near-Miss Recording
# =============================================================================

@router.post("/near-misses", response_model=NearMissResponse, status_code=status.HTTP_201_CREATED)
async def create_near_miss(
    request: Request,
    near_miss_data: NearMissCreate,
    current_user: User = Depends(require_permission("incidents.create")),
    db: AsyncSession = Depends(get_db),
):
    """
    Record a near-miss (blocked attack).
    
    Near-misses are crucial for proving control effectiveness.
    They show what WOULD have happened without the controls.
    """
    import json
    
    near_miss = NearMiss(
        near_miss_id=generate_near_miss_id(),
        title=near_miss_data.title,
        description=near_miss_data.description,
        would_have_been_type=near_miss_data.would_have_been_type,
        would_have_been_severity=near_miss_data.would_have_been_severity,
        occurred_at=near_miss_data.occurred_at,
        target_system_id=near_miss_data.target_system_id,
        attack_vector=near_miss_data.attack_vector,
        attack_details=near_miss_data.attack_details,
        reported_by_id=current_user.id,
    )
    
    if near_miss_data.blocking_controls:
        near_miss.blocking_controls = json.dumps(near_miss_data.blocking_controls)
    
    if near_miss_data.detection_controls:
        near_miss.detection_controls = json.dumps(near_miss_data.detection_controls)
    
    db.add(near_miss)
    await db.commit()
    await db.refresh(near_miss)
    
    return NearMissResponse(
        id=near_miss.id,
        near_miss_id=near_miss.near_miss_id,
        title=near_miss.title,
        description=near_miss.description,
        would_have_been_type=near_miss.would_have_been_type,
        would_have_been_severity=near_miss.would_have_been_severity,
        occurred_at=near_miss.occurred_at,
        blocking_controls=near_miss.get_blocking_controls(),
        reported_by=current_user.email,
        created_at=near_miss.created_at,
    )


# =============================================================================
# Correlation Analysis
# =============================================================================

@router.get("/correlation/stats", response_model=ComplianceSecurityCorrelation)
async def get_correlation_stats(
    current_user: User = Depends(require_permission("incidents.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get statistics correlating compliance gaps with security incidents.
    
    This is the key research endpoint for proving/disproving:
    "Does compliance = security?"
    """
    # Count total incidents
    result = await db.execute(select(func.count(SecurityIncident.id)))
    total_incidents = result.scalar() or 0
    
    # Count incidents with compliance gap
    result = await db.execute(
        select(func.count(SecurityIncident.id))
        .where(SecurityIncident.non_compliant_controls.isnot(None))
    )
    incidents_with_gap = result.scalar() or 0
    
    incidents_without_gap = total_incidents - incidents_with_gap
    gap_percentage = (incidents_with_gap / total_incidents * 100) if total_incidents > 0 else 0
    
    # Count near misses
    result = await db.execute(select(func.count(NearMiss.id)))
    total_near_misses = result.scalar() or 0
    
    # Get all near misses to count controls
    result = await db.execute(select(NearMiss))
    near_misses = result.scalars().all()
    
    controls_that_blocked = {}
    for nm in near_misses:
        for control in nm.get_blocking_controls():
            controls_that_blocked[control] = controls_that_blocked.get(control, 0) + 1
    
    # TODO: Implement top_failing_controls and incidents_over_time
    # This requires more sophisticated queries against the knowledge graph
    
    return ComplianceSecurityCorrelation(
        total_incidents=total_incidents,
        incidents_with_compliance_gap=incidents_with_gap,
        incidents_without_gap=incidents_without_gap,
        gap_percentage=round(gap_percentage, 2),
        total_near_misses=total_near_misses,
        controls_that_blocked=controls_that_blocked,
        top_failing_controls=[],  # TODO: Implement
        incidents_over_time=[],   # TODO: Implement
    )

