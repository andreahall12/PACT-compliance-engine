"""
Audit logging helper functions.

Centralizes audit log creation to reduce code duplication across endpoints.
"""

from typing import Optional, Dict, Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.audit import AuditLog, AuditAction
from app.auth.dependencies import get_client_ip, get_user_agent


def create_audit_log(
    request: Request,
    user: User,
    action: AuditAction,
    resource_type: str,
    resource_id: str,
    resource_name: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Create an audit log entry.
    
    This is a synchronous helper that creates an AuditLog object.
    The caller is responsible for adding it to the session and committing.
    
    Args:
        request: FastAPI Request object (for IP and user agent)
        user: The user performing the action
        action: The audit action type
        resource_type: Type of resource (e.g., "user", "system", "document")
        resource_id: Identifier of the resource
        resource_name: Optional human-readable name
        details: Optional dictionary of additional details
        
    Returns:
        AuditLog instance (not yet added to session)
        
    Example:
        audit = create_audit_log(
            request=request,
            user=current_user,
            action=AuditAction.USER_CREATED,
            resource_type="user",
            resource_id=new_user.email,
            resource_name=new_user.full_name,
            details={"role": new_user.role.value}
        )
        db.add(audit)
    """
    return AuditLog.create(
        action=action,
        user_id=user.id,
        user_email=user.email,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )


async def log_action(
    db: AsyncSession,
    request: Request,
    user: User,
    action: AuditAction,
    resource_type: str,
    resource_id: str,
    resource_name: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Create and add an audit log entry to the session.
    
    This is an async helper that creates and adds the audit log.
    The caller should commit the session.
    
    Args:
        db: AsyncSession to add the audit log to
        request: FastAPI Request object (for IP and user agent)
        user: The user performing the action
        action: The audit action type
        resource_type: Type of resource (e.g., "user", "system", "document")
        resource_id: Identifier of the resource
        resource_name: Optional human-readable name
        details: Optional dictionary of additional details
        
    Returns:
        AuditLog instance (added to session but not committed)
        
    Example:
        await log_action(
            db=db,
            request=request,
            user=current_user,
            action=AuditAction.USER_CREATED,
            resource_type="user",
            resource_id=new_user.email,
            resource_name=new_user.full_name,
            details={"role": new_user.role.value}
        )
        await db.commit()
    """
    audit = create_audit_log(
        request=request,
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details,
    )
    db.add(audit)
    return audit

