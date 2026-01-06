"""
Event ingestion endpoint.

Receives security events, runs compliance checks, and stores results.
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime

from fastapi import APIRouter, HTTPException, Body, Depends, status
from pydantic import BaseModel, Field, field_validator

from app.core.engine import run_assessment
from app.core.store import db
from app.models.user import User
from app.auth.dependencies import get_current_active_user

router = APIRouter()


# ============================================================================
# Event Schema Definitions
# ============================================================================

class FileInfo(BaseModel):
    """File information for file_access events."""
    name: str = Field(..., min_length=1, max_length=500, description="File name")
    path: Optional[str] = Field(None, max_length=1000, description="Full file path")


class UserInfo(BaseModel):
    """User information for events."""
    name: str = Field(..., min_length=1, max_length=255, description="Username")
    id: Optional[str] = Field(None, description="User ID")


class DestinationInfo(BaseModel):
    """Network destination information."""
    ip: Optional[str] = Field(None, description="Destination IP address")
    port: int = Field(..., ge=0, le=65535, description="Destination port")
    hostname: Optional[str] = Field(None, description="Destination hostname")


class FileAccessEvent(BaseModel):
    """File access event schema."""
    type: str = Field("file_access", pattern="^file_access$")
    id: Optional[str] = Field(None, description="Unique event ID")
    system: Optional[str] = Field(None, description="Source system name")
    file: FileInfo
    user: UserInfo
    timestamp: Optional[datetime] = Field(None, description="Event timestamp")
    source_url: Optional[str] = Field(None, description="Link to original log")


class NetworkConnectionEvent(BaseModel):
    """Network connection event schema."""
    type: str = Field("network_connection", pattern="^network_connection$")
    id: Optional[str] = Field(None, description="Unique event ID")
    system: Optional[str] = Field(None, description="Source system name")
    destination: DestinationInfo
    protocol: str = Field("tcp", description="Protocol (tcp, udp, etc.)")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp")
    source_url: Optional[str] = Field(None, description="Link to original log")


class AuthenticationEvent(BaseModel):
    """Authentication event schema."""
    type: str = Field("authentication", pattern="^authentication$")
    id: Optional[str] = Field(None, description="Unique event ID")
    system: Optional[str] = Field(None, description="Source system name")
    user: UserInfo
    result: str = Field(..., description="Authentication result (success, failure, mfa_required)")
    method: str = Field("password", description="Auth method (password, sso, mfa, certificate)")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp")
    source_url: Optional[str] = Field(None, description="Link to original log")


class APICallEvent(BaseModel):
    """API call event schema."""
    type: str = Field("api_call", pattern="^api_call$")
    id: Optional[str] = Field(None, description="Unique event ID")
    system: Optional[str] = Field(None, description="Source system name")
    endpoint: str = Field(..., description="API endpoint path")
    method: str = Field("GET", description="HTTP method")
    status_code: int = Field(..., ge=100, le=599, description="Response status code")
    user: Optional[UserInfo] = Field(None, description="User making the call")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp")
    source_url: Optional[str] = Field(None, description="Link to original log")


class ConfigChangeEvent(BaseModel):
    """Configuration change event schema."""
    type: str = Field("config_change", pattern="^config_change$")
    id: Optional[str] = Field(None, description="Unique event ID")
    system: Optional[str] = Field(None, description="Source system name")
    key: str = Field(..., description="Configuration key/path")
    old_value: Optional[Any] = Field(None, description="Previous value")
    new_value: Any = Field(..., description="New value")
    user: Optional[UserInfo] = Field(None, description="User who made the change")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp")
    source_url: Optional[str] = Field(None, description="Link to original log")


class GenericEvent(BaseModel):
    """Generic event for unsupported types."""
    type: str = Field(..., description="Event type")
    id: Optional[str] = Field(None, description="Unique event ID")
    system: Optional[str] = Field(None, description="Source system name")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp")
    source_url: Optional[str] = Field(None, description="Link to original log")
    
    class Config:
        extra = "allow"  # Allow additional fields


# Union of all event types
Event = Union[
    FileAccessEvent,
    NetworkConnectionEvent,
    AuthenticationEvent,
    APICallEvent,
    ConfigChangeEvent,
    GenericEvent,
]


class IngestRequest(BaseModel):
    """Request body for event ingestion."""
    events: List[Dict[str, Any]] = Field(..., min_length=1, max_length=1000, description="List of events to ingest")
    target_systems: List[str] = Field(default_factory=list, description="Filter to specific systems")
    target_frameworks: List[str] = Field(default_factory=list, description="Filter to specific frameworks/controls")
    validate_strict: bool = Field(False, description="If true, reject on any validation error")

    @field_validator('events')
    @classmethod
    def validate_events_have_type(cls, v):
        """Ensure all events have a type field."""
        for i, event in enumerate(v):
            if not isinstance(event, dict):
                raise ValueError(f"Event {i} must be a dictionary")
            if 'type' not in event:
                raise ValueError(f"Event {i} missing required 'type' field")
        return v


class IngestResponse(BaseModel):
    """Response from event ingestion."""
    status: str
    scan_id: str
    events_received: int
    events_processed: int
    triples_generated: int
    validation_warnings: List[str] = []


class ValidationResult(BaseModel):
    """Result of event validation."""
    valid: bool
    event_index: int
    event_type: str
    errors: List[str] = []


class ValidateRequest(BaseModel):
    """Request to validate events without ingesting."""
    events: List[Dict[str, Any]]


class ValidateResponse(BaseModel):
    """Response from event validation."""
    valid: bool
    total_events: int
    valid_count: int
    invalid_count: int
    results: List[ValidationResult]


def validate_event(event: Dict[str, Any], index: int) -> ValidationResult:
    """Validate a single event against its schema."""
    event_type = event.get("type", "unknown")
    errors = []
    
    schema_map = {
        "file_access": FileAccessEvent,
        "network_connection": NetworkConnectionEvent,
        "authentication": AuthenticationEvent,
        "api_call": APICallEvent,
        "config_change": ConfigChangeEvent,
    }
    
    schema = schema_map.get(event_type)
    
    if schema:
        try:
            schema.model_validate(event)
        except Exception as e:
            errors.append(str(e))
    else:
        # Use generic schema
        try:
            GenericEvent.model_validate(event)
        except Exception as e:
            errors.append(str(e))
    
    return ValidationResult(
        valid=len(errors) == 0,
        event_index=index,
        event_type=event_type,
        errors=errors,
    )


@router.post("", response_model=IngestResponse)
async def ingest_events(
    request: IngestRequest = Body(...),
    current_user: User = Depends(get_current_active_user),
):
    """
    Ingest a list of security events, run compliance checks, and store results.
    
    Supports the following event types:
    - `file_access`: File read/write/execute events
    - `network_connection`: Network connection events (ports, protocols)
    - `authentication`: Login/logout/auth failure events
    - `api_call`: API invocation events
    - `config_change`: Configuration modification events
    
    Events are mapped to UCO (Unified Cyber Ontology) observables, validated
    against SHACL policies, and stored in the knowledge graph.
    
    Returns the scan ID which can be used to query results.
    """
    if not request.events:
        raise HTTPException(status_code=400, detail="No events provided")
    
    # Validate events
    validation_warnings = []
    valid_events = []
    
    for i, event in enumerate(request.events):
        result = validate_event(event, i)
        if result.valid:
            valid_events.append(event)
        else:
            if request.validate_strict:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Event {i} validation failed: {result.errors}",
                )
            validation_warnings.append(f"Event {i} ({result.event_type}): {result.errors}")
    
    if not valid_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No valid events to process",
        )
    
    try:
        scan_uri, graph_data = run_assessment(
            valid_events,
            target_systems=request.target_systems or None,
            target_frameworks=request.target_frameworks or None,
        )
        
        # Save to Store
        db.add_graph(scan_uri, graph_data)
        
        return IngestResponse(
            status="success",
            scan_id=scan_uri,
            events_received=len(request.events),
            events_processed=len(valid_events),
            triples_generated=len(graph_data),
            validation_warnings=validation_warnings[:10],  # Limit warnings
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/validate", response_model=ValidateResponse)
async def validate_events(
    request: ValidateRequest = Body(...),
    current_user: User = Depends(get_current_active_user),
):
    """
    Validate events without ingesting them.
    
    Useful for testing event format before sending to production.
    Returns detailed validation results for each event.
    """
    results = []
    valid_count = 0
    
    for i, event in enumerate(request.events):
        result = validate_event(event, i)
        results.append(result)
        if result.valid:
            valid_count += 1
    
    return ValidateResponse(
        valid=valid_count == len(request.events),
        total_events=len(request.events),
        valid_count=valid_count,
        invalid_count=len(request.events) - valid_count,
        results=results,
    )


@router.get("/schema/{event_type}")
async def get_event_schema(
    event_type: str,
    current_user: User = Depends(get_current_active_user),
):
    """
    Get the JSON schema for a specific event type.
    
    Useful for integrations to understand expected event format.
    """
    schema_map = {
        "file_access": FileAccessEvent,
        "network_connection": NetworkConnectionEvent,
        "authentication": AuthenticationEvent,
        "api_call": APICallEvent,
        "config_change": ConfigChangeEvent,
        "generic": GenericEvent,
    }
    
    schema_class = schema_map.get(event_type)
    
    if not schema_class:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown event type: {event_type}. Available types: {list(schema_map.keys())}",
        )
    
    return schema_class.model_json_schema()


@router.get("/types")
async def list_event_types(
    current_user: User = Depends(get_current_active_user),
):
    """
    List all supported event types with descriptions.
    """
    return {
        "event_types": [
            {
                "type": "file_access",
                "description": "File read/write/execute events from file integrity monitoring",
                "required_fields": ["file.name", "user.name"],
            },
            {
                "type": "network_connection",
                "description": "Network connection events from firewalls, IDS/IPS",
                "required_fields": ["destination.port", "protocol"],
            },
            {
                "type": "authentication",
                "description": "Authentication events from identity providers",
                "required_fields": ["user.name", "result", "method"],
            },
            {
                "type": "api_call",
                "description": "API invocation events from API gateways",
                "required_fields": ["endpoint", "method", "status_code"],
            },
            {
                "type": "config_change",
                "description": "Configuration changes from CMDB or config management",
                "required_fields": ["key", "new_value"],
            },
        ],
        "common_fields": {
            "id": "Unique event identifier (optional, auto-generated if missing)",
            "system": "Source system name (used for filtering and linking)",
            "timestamp": "ISO8601 timestamp (optional)",
            "source_url": "Link to original log entry (optional)",
        },
    }
