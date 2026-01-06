"""
Scheduled Assessment Jobs endpoints.

Manages:
- Recurring compliance scans
- Scheduled ingestion from sources
- Job execution and history
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum as PyEnum

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from pydantic import BaseModel, Field

from app.models.user import User
from app.auth.dependencies import require_permission

router = APIRouter()


class ScheduleFrequency(str, PyEnum):
    """Schedule frequency options."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


class ScheduleStatus(str, PyEnum):
    """Schedule status."""
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


class JobStatus(str, PyEnum):
    """Individual job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScheduleCreate(BaseModel):
    """Create a new schedule."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    frequency: ScheduleFrequency
    cron_expression: Optional[str] = Field(None, description="Custom cron expression for CUSTOM frequency")
    target_systems: List[str] = Field(default_factory=list, description="System IDs to scan")
    target_frameworks: List[str] = Field(default_factory=list, description="Framework IDs to check")
    notify_on_failure: bool = True
    notify_on_success: bool = False


class ScheduleUpdate(BaseModel):
    """Update a schedule."""
    name: Optional[str] = None
    description: Optional[str] = None
    frequency: Optional[ScheduleFrequency] = None
    cron_expression: Optional[str] = None
    target_systems: Optional[List[str]] = None
    target_frameworks: Optional[List[str]] = None
    status: Optional[ScheduleStatus] = None
    notify_on_failure: Optional[bool] = None
    notify_on_success: Optional[bool] = None


class ScheduleResponse(BaseModel):
    """Schedule response model."""
    id: str
    name: str
    description: Optional[str]
    frequency: str
    cron_expression: Optional[str]
    target_systems: List[str]
    target_frameworks: List[str]
    status: str
    notify_on_failure: bool
    notify_on_success: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_at: datetime
    created_by: str


class JobExecution(BaseModel):
    """Record of a job execution."""
    id: str
    schedule_id: str
    schedule_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    events_processed: int
    failures_found: int
    error_message: Optional[str]


class JobListResponse(BaseModel):
    """List of job executions."""
    jobs: List[JobExecution]
    total: int


# In-memory storage for demo
_schedules: Dict[str, dict] = {}
_job_history: List[dict] = []


def calculate_next_run(frequency: ScheduleFrequency, last_run: Optional[datetime] = None) -> datetime:
    """Calculate the next run time based on frequency."""
    base = last_run or datetime.now(timezone.utc)
    
    if frequency == ScheduleFrequency.HOURLY:
        return base + timedelta(hours=1)
    elif frequency == ScheduleFrequency.DAILY:
        return base + timedelta(days=1)
    elif frequency == ScheduleFrequency.WEEKLY:
        return base + timedelta(weeks=1)
    elif frequency == ScheduleFrequency.MONTHLY:
        return base + timedelta(days=30)
    else:
        return base + timedelta(days=1)


@router.get("", response_model=List[ScheduleResponse])
async def list_schedules(
    status_filter: Optional[ScheduleStatus] = Query(None, alias="status"),
    current_user: User = Depends(require_permission("schedules.read")),
):
    """List all scheduled jobs."""
    schedules = list(_schedules.values())
    
    if status_filter:
        schedules = [s for s in schedules if s.get("status") == status_filter.value]
    
    return [
        ScheduleResponse(
            id=s["id"],
            name=s["name"],
            description=s.get("description"),
            frequency=s["frequency"],
            cron_expression=s.get("cron_expression"),
            target_systems=s.get("target_systems", []),
            target_frameworks=s.get("target_frameworks", []),
            status=s.get("status", "active"),
            notify_on_failure=s.get("notify_on_failure", True),
            notify_on_success=s.get("notify_on_success", False),
            last_run=s.get("last_run"),
            next_run=s.get("next_run"),
            created_at=s["created_at"],
            created_by=s["created_by"],
        )
        for s in schedules
    ]


@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    schedule_data: ScheduleCreate,
    current_user: User = Depends(require_permission("schedules.create")),
):
    """Create a new scheduled job."""
    schedule_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    schedule = {
        "id": schedule_id,
        "name": schedule_data.name,
        "description": schedule_data.description,
        "frequency": schedule_data.frequency.value,
        "cron_expression": schedule_data.cron_expression,
        "target_systems": schedule_data.target_systems,
        "target_frameworks": schedule_data.target_frameworks,
        "status": ScheduleStatus.ACTIVE.value,
        "notify_on_failure": schedule_data.notify_on_failure,
        "notify_on_success": schedule_data.notify_on_success,
        "last_run": None,
        "next_run": calculate_next_run(schedule_data.frequency),
        "created_at": now,
        "created_by": current_user.email,
    }
    
    _schedules[schedule_id] = schedule
    
    return ScheduleResponse(**schedule)


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: str,
    current_user: User = Depends(require_permission("schedules.read")),
):
    """Get a specific schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    s = _schedules[schedule_id]
    return ScheduleResponse(
        id=s["id"],
        name=s["name"],
        description=s.get("description"),
        frequency=s["frequency"],
        cron_expression=s.get("cron_expression"),
        target_systems=s.get("target_systems", []),
        target_frameworks=s.get("target_frameworks", []),
        status=s.get("status", "active"),
        notify_on_failure=s.get("notify_on_failure", True),
        notify_on_success=s.get("notify_on_success", False),
        last_run=s.get("last_run"),
        next_run=s.get("next_run"),
        created_at=s["created_at"],
        created_by=s["created_by"],
    )


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: str,
    schedule_data: ScheduleUpdate,
    current_user: User = Depends(require_permission("schedules.update")),
):
    """Update a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    schedule = _schedules[schedule_id]
    
    for field, value in schedule_data.model_dump(exclude_unset=True).items():
        if value is not None:
            if field == "frequency":
                schedule["frequency"] = value.value if hasattr(value, "value") else value
            elif field == "status":
                schedule["status"] = value.value if hasattr(value, "value") else value
            else:
                schedule[field] = value
    
    s = schedule
    return ScheduleResponse(
        id=s["id"],
        name=s["name"],
        description=s.get("description"),
        frequency=s["frequency"],
        cron_expression=s.get("cron_expression"),
        target_systems=s.get("target_systems", []),
        target_frameworks=s.get("target_frameworks", []),
        status=s.get("status", "active"),
        notify_on_failure=s.get("notify_on_failure", True),
        notify_on_success=s.get("notify_on_success", False),
        last_run=s.get("last_run"),
        next_run=s.get("next_run"),
        created_at=s["created_at"],
        created_by=s["created_by"],
    )


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    current_user: User = Depends(require_permission("schedules.delete")),
):
    """Delete a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    del _schedules[schedule_id]


@router.post("/{schedule_id}/run", response_model=JobExecution)
async def trigger_schedule(
    schedule_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("schedules.execute")),
):
    """Manually trigger a scheduled job to run now."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    schedule = _schedules[schedule_id]
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    job = {
        "id": job_id,
        "schedule_id": schedule_id,
        "schedule_name": schedule["name"],
        "status": JobStatus.PENDING.value,
        "started_at": now,
        "completed_at": None,
        "duration_seconds": None,
        "events_processed": 0,
        "failures_found": 0,
        "error_message": None,
    }
    
    _job_history.insert(0, job)
    
    # In production, background_tasks would run the actual scan
    # For demo, simulate completion
    import random
    job["status"] = JobStatus.COMPLETED.value
    job["completed_at"] = now + timedelta(seconds=random.uniform(5, 30))
    job["duration_seconds"] = (job["completed_at"] - now).total_seconds()
    job["events_processed"] = random.randint(50, 500)
    job["failures_found"] = random.randint(0, 10)
    
    # Update schedule
    schedule["last_run"] = now
    schedule["next_run"] = calculate_next_run(
        ScheduleFrequency(schedule["frequency"]),
        now
    )
    
    return JobExecution(**job)


@router.post("/{schedule_id}/pause")
async def pause_schedule(
    schedule_id: str,
    current_user: User = Depends(require_permission("schedules.update")),
):
    """Pause a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    _schedules[schedule_id]["status"] = ScheduleStatus.PAUSED.value
    return {"status": "paused", "schedule_id": schedule_id}


@router.post("/{schedule_id}/resume")
async def resume_schedule(
    schedule_id: str,
    current_user: User = Depends(require_permission("schedules.update")),
):
    """Resume a paused schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    schedule = _schedules[schedule_id]
    schedule["status"] = ScheduleStatus.ACTIVE.value
    schedule["next_run"] = calculate_next_run(
        ScheduleFrequency(schedule["frequency"])
    )
    
    return {"status": "active", "schedule_id": schedule_id, "next_run": schedule["next_run"]}


@router.get("/{schedule_id}/history", response_model=JobListResponse)
async def get_schedule_history(
    schedule_id: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_permission("schedules.read")),
):
    """Get execution history for a schedule."""
    if schedule_id not in _schedules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )
    
    jobs = [j for j in _job_history if j["schedule_id"] == schedule_id]
    
    return JobListResponse(
        jobs=[JobExecution(**j) for j in jobs[:limit]],
        total=len(jobs),
    )


@router.get("/jobs/recent", response_model=JobListResponse)
async def get_recent_jobs(
    limit: int = Query(50, ge=1, le=200),
    status_filter: Optional[JobStatus] = Query(None, alias="status"),
    current_user: User = Depends(require_permission("schedules.read")),
):
    """Get recent job executions across all schedules."""
    jobs = _job_history.copy()
    
    if status_filter:
        jobs = [j for j in jobs if j["status"] == status_filter.value]
    
    return JobListResponse(
        jobs=[JobExecution(**j) for j in jobs[:limit]],
        total=len(jobs),
    )

