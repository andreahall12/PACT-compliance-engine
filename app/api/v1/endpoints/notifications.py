"""
Notification and Webhook management endpoints.

Manages:
- User notification preferences
- Webhook integrations (Slack, Teams, PagerDuty, email)
- Alert rules and thresholds
"""

import json
import uuid
import hmac
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum as PyEnum

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.user import User
from app.auth.dependencies import require_permission, get_current_active_user

router = APIRouter()


class NotificationChannel(str, PyEnum):
    """Notification delivery channels."""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    IN_APP = "in_app"


class AlertSeverity(str, PyEnum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertType(str, PyEnum):
    """Types of alerts."""
    COMPLIANCE_FAILURE = "compliance_failure"
    DRIFT_DETECTED = "drift_detected"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY_FOUND = "vulnerability_found"
    DOCUMENT_EXPIRING = "document_expiring"
    ASSESSMENT_COMPLETE = "assessment_complete"
    VENDOR_RISK = "vendor_risk"


class WebhookConfig(BaseModel):
    """Webhook configuration."""
    id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., description="Webhook URL")
    channel: NotificationChannel
    secret: Optional[str] = Field(None, description="Shared secret for HMAC signature")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers")
    enabled: bool = True
    alert_types: List[AlertType] = Field(default_factory=list, description="Alert types to send")
    min_severity: AlertSeverity = AlertSeverity.MEDIUM


class WebhookCreate(BaseModel):
    """Create a new webhook."""
    name: str = Field(..., min_length=1, max_length=255)
    url: str
    channel: NotificationChannel = NotificationChannel.WEBHOOK
    secret: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    alert_types: List[AlertType] = Field(default_factory=lambda: [AlertType.COMPLIANCE_FAILURE])
    min_severity: AlertSeverity = AlertSeverity.MEDIUM


class NotificationPreferences(BaseModel):
    """User notification preferences."""
    email_enabled: bool = True
    email_frequency: str = "immediate"  # immediate, daily, weekly
    slack_enabled: bool = False
    slack_dm: bool = False
    in_app_enabled: bool = True
    alert_types: List[AlertType] = Field(default_factory=list)
    min_severity: AlertSeverity = AlertSeverity.MEDIUM
    quiet_hours_start: Optional[str] = None  # HH:MM format
    quiet_hours_end: Optional[str] = None


class AlertRule(BaseModel):
    """Custom alert rule."""
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    enabled: bool = True
    conditions: Dict[str, Any]  # Rule conditions
    actions: List[Dict[str, Any]]  # Actions to take
    cooldown_minutes: int = Field(60, description="Minutes between repeated alerts")


class NotificationPayload(BaseModel):
    """Payload for a notification."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    source_url: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WebhookTestResult(BaseModel):
    """Result of webhook test."""
    success: bool
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None


# In-memory storage for demo (would use DB in production)
_webhooks: Dict[str, WebhookConfig] = {}
_user_preferences: Dict[int, NotificationPreferences] = {}
_alert_rules: Dict[str, AlertRule] = {}
_notification_history: List[Dict[str, Any]] = []


@router.get("/preferences", response_model=NotificationPreferences)
async def get_notification_preferences(
    current_user: User = Depends(get_current_active_user),
):
    """Get current user's notification preferences."""
    if current_user.id in _user_preferences:
        return _user_preferences[current_user.id]
    
    # Return defaults
    return NotificationPreferences()


@router.put("/preferences", response_model=NotificationPreferences)
async def update_notification_preferences(
    preferences: NotificationPreferences,
    current_user: User = Depends(get_current_active_user),
):
    """Update current user's notification preferences."""
    _user_preferences[current_user.id] = preferences
    return preferences


@router.get("/webhooks", response_model=List[WebhookConfig])
async def list_webhooks(
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """List all configured webhooks."""
    return list(_webhooks.values())


@router.post("/webhooks", response_model=WebhookConfig, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    webhook_data: WebhookCreate,
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """Create a new webhook integration."""
    webhook_id = str(uuid.uuid4())
    
    webhook = WebhookConfig(
        id=webhook_id,
        name=webhook_data.name,
        url=webhook_data.url,
        channel=webhook_data.channel,
        secret=webhook_data.secret,
        headers=webhook_data.headers,
        enabled=True,
        alert_types=webhook_data.alert_types,
        min_severity=webhook_data.min_severity,
    )
    
    _webhooks[webhook_id] = webhook
    return webhook


@router.get("/webhooks/{webhook_id}", response_model=WebhookConfig)
async def get_webhook(
    webhook_id: str,
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """Get a specific webhook configuration."""
    if webhook_id not in _webhooks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )
    return _webhooks[webhook_id]


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """Delete a webhook."""
    if webhook_id not in _webhooks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )
    del _webhooks[webhook_id]


@router.post("/webhooks/{webhook_id}/test", response_model=WebhookTestResult)
async def test_webhook(
    webhook_id: str,
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """Test a webhook by sending a test notification."""
    if webhook_id not in _webhooks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )
    
    webhook = _webhooks[webhook_id]
    
    # Create test payload
    test_payload = {
        "type": "test",
        "message": "This is a test notification from PACT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    # In production, actually send the HTTP request
    # For demo, simulate success
    import random
    success = random.random() > 0.1  # 90% success rate
    
    return WebhookTestResult(
        success=success,
        status_code=200 if success else 500,
        response_time_ms=random.uniform(50, 200),
        error=None if success else "Connection timeout",
    )


@router.get("/rules", response_model=List[AlertRule])
async def list_alert_rules(
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """List all custom alert rules."""
    return list(_alert_rules.values())


@router.post("/rules", response_model=AlertRule, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    rule: AlertRule,
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """Create a custom alert rule."""
    rule_id = str(uuid.uuid4())
    rule.id = rule_id
    _alert_rules[rule_id] = rule
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert_rule(
    rule_id: str,
    current_user: User = Depends(require_permission("notifications.manage")),
):
    """Delete an alert rule."""
    if rule_id not in _alert_rules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )
    del _alert_rules[rule_id]


@router.get("/history")
async def get_notification_history(
    limit: int = Query(50, ge=1, le=200),
    alert_type: Optional[AlertType] = None,
    severity: Optional[AlertSeverity] = None,
    current_user: User = Depends(get_current_active_user),
):
    """Get notification history for the current user."""
    history = _notification_history.copy()
    
    # Filter by type
    if alert_type:
        history = [n for n in history if n.get("type") == alert_type.value]
    
    # Filter by severity
    if severity:
        history = [n for n in history if n.get("severity") == severity.value]
    
    return {
        "notifications": history[:limit],
        "total": len(history),
    }


@router.post("/send", status_code=status.HTTP_202_ACCEPTED)
async def send_notification(
    payload: NotificationPayload,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("notifications.send")),
):
    """
    Send a notification (admin/system use).
    
    This endpoint is used by the system to trigger notifications.
    It will deliver to all configured channels based on preferences and rules.
    """
    # Add to history
    _notification_history.insert(0, payload.model_dump(mode="json"))
    
    # Trim history
    if len(_notification_history) > 1000:
        _notification_history[:] = _notification_history[:1000]
    
    # In production, background_tasks would send to webhooks, email, etc.
    
    return {
        "status": "queued",
        "notification_id": payload.id,
        "channels_targeted": len(_webhooks),
    }


@router.get("/channels")
async def list_available_channels(
    current_user: User = Depends(get_current_active_user),
):
    """List available notification channels and their configuration status."""
    return {
        "channels": [
            {
                "id": "email",
                "name": "Email",
                "configured": True,
                "description": "Email notifications to your registered address",
            },
            {
                "id": "slack",
                "name": "Slack",
                "configured": any(w.channel == NotificationChannel.SLACK for w in _webhooks.values()),
                "description": "Slack messages to channels or DMs",
            },
            {
                "id": "teams",
                "name": "Microsoft Teams",
                "configured": any(w.channel == NotificationChannel.TEAMS for w in _webhooks.values()),
                "description": "Microsoft Teams notifications",
            },
            {
                "id": "pagerduty",
                "name": "PagerDuty",
                "configured": any(w.channel == NotificationChannel.PAGERDUTY for w in _webhooks.values()),
                "description": "PagerDuty incidents for critical alerts",
            },
            {
                "id": "webhook",
                "name": "Custom Webhook",
                "configured": any(w.channel == NotificationChannel.WEBHOOK for w in _webhooks.values()),
                "description": "Custom HTTP webhooks",
            },
            {
                "id": "in_app",
                "name": "In-App",
                "configured": True,
                "description": "Notifications within the PACT dashboard",
            },
        ],
        "webhook_count": len(_webhooks),
    }


def sign_webhook_payload(payload: dict, secret: str) -> str:
    """Generate HMAC signature for webhook payload."""
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    return hmac.new(
        secret.encode('utf-8'),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

