"""
API Router configuration.

Aggregates all v1 API endpoints with proper tagging and prefixes.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    compliance,
    chat,
    ingest,
    users,
    systems,
    documents,
    incidents,
    history,
    export,
    catalog,
    scans,
    policies,
    vendors,
    sbom,
    notifications,
    websocket,
    schedules,
)

api_router = APIRouter()

# Authentication (no auth required for login/refresh)
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["authentication"]
)

# User management (requires admin/compliance officer)
api_router.include_router(
    users.router,
    prefix="/users",
    tags=["users"]
)

# System management
api_router.include_router(
    systems.router,
    prefix="/systems",
    tags=["systems"]
)

# Document management
api_router.include_router(
    documents.router,
    prefix="/documents",
    tags=["documents"]
)

# Compliance data (blast radius, drift, threats)
api_router.include_router(
    compliance.router,
    prefix="/compliance",
    tags=["compliance"]
)

# AI Auditor chat
api_router.include_router(
    chat.router,
    prefix="/chat",
    tags=["chat"]
)

# Event ingestion
api_router.include_router(
    ingest.router,
    prefix="/ingest",
    tags=["ingest"]
)

# Incident management
api_router.include_router(
    incidents.router,
    prefix="/incidents",
    tags=["incidents"]
)

# Historical view / time machine
api_router.include_router(
    history.router,
    prefix="/history",
    tags=["history"]
)

# Export (OSCAL, POA&M)
api_router.include_router(
    export.router,
    prefix="/export",
    tags=["export"]
)

# Catalog (dynamic filter data)
api_router.include_router(
    catalog.router,
    prefix="/catalog",
    tags=["catalog"]
)

# Scans history
api_router.include_router(
    scans.router,
    prefix="/scans",
    tags=["scans"]
)

# Policy management
api_router.include_router(
    policies.router,
    prefix="/policies",
    tags=["policies"]
)

# Vendor risk management
api_router.include_router(
    vendors.router,
    prefix="/vendors",
    tags=["vendors"]
)

# SBOM management
api_router.include_router(
    sbom.router,
    prefix="/sbom",
    tags=["sbom"]
)

# Notifications and webhooks
api_router.include_router(
    notifications.router,
    prefix="/notifications",
    tags=["notifications"]
)

# WebSocket for real-time updates
api_router.include_router(
    websocket.router,
    prefix="/realtime",
    tags=["realtime"]
)

# Scheduled jobs
api_router.include_router(
    schedules.router,
    prefix="/schedules",
    tags=["schedules"]
)
