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
