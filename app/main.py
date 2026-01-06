"""
PACT - Policy Automation and Compliance Traceability

Main FastAPI application with security hardening.
"""

import os
import secrets
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.api import api_router
from app.api.v1.endpoints import visualize
from app.core.config import get_cors_allow_origins, PACT_API_KEY
from app.core.database import init_db, close_db

from dotenv import load_dotenv

load_dotenv()


# =============================================================================
# Application Lifespan (startup/shutdown)
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown events."""
    # Startup
    print("🚀 Starting PACT Compliance Engine...")
    
    # Initialize database
    await init_db()
    print("✅ Database initialized")
    
    # Create default admin user if none exists
    await create_default_admin_if_needed()
    
    yield
    
    # Shutdown
    print("👋 Shutting down PACT...")
    await close_db()


async def create_default_admin_if_needed():
    """Create a default admin user if no users exist."""
    from sqlalchemy import select, func
    from app.core.database import async_session_maker
    from app.models.user import User, UserRole
    from app.auth.password import generate_temp_password, hash_password
    
    async with async_session_maker() as session:
        result = await session.execute(select(func.count(User.id)))
        user_count = result.scalar()
        
        if user_count == 0:
            # Generate a secure temporary password
            temp_password = generate_temp_password()
            
            admin = User(
                email="admin@pact.local",
                full_name="PACT Administrator",
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True,
            )
            admin.set_password(temp_password)
            
            session.add(admin)
            await session.commit()
            
            print("=" * 60)
            print("🔐 DEFAULT ADMIN ACCOUNT CREATED")
            print(f"   Email:    admin@pact.local")
            print(f"   Password: {temp_password}")
            print("   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!")
            print("=" * 60)


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="PACT Compliance API",
    version="2.0.0",
    description="Policy Automation and Compliance Traceability Engine",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "true").lower() == "true" else None,
    redoc_url="/redoc" if os.getenv("ENABLE_DOCS", "true").lower() == "true" else None,
)


# =============================================================================
# Security Middleware
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection (legacy, but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions policy (disable unused features)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        
        # Content Security Policy (adjust for your frontend needs)
        if request.url.path.startswith("/visualize"):
            # More permissive CSP for the dashboard
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "font-src 'self' https://cdnjs.cloudflare.com; "
                "img-src 'self' data:; "
                "connect-src 'self' http://localhost:* ws://localhost:*"
            )
        else:
            # Strict CSP for API endpoints
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        
        # HSTS (only enable in production with HTTPS)
        if os.getenv("ENABLE_HSTS", "false").lower() == "true":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID for tracing."""
    
    async def dispatch(self, request: Request, call_next: Callable):
        request_id = request.headers.get("X-Request-ID") or secrets.token_urlsafe(8)
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response


# Legacy API key middleware (for backward compatibility)
# Will be replaced by JWT auth, but kept for API-only access
class LegacyAPIKeyMiddleware(BaseHTTPMiddleware):
    """
    Legacy API key authentication for backward compatibility.
    
    Checks for PACT_API_KEY env var and validates requests.
    This is separate from JWT-based user authentication.
    """
    
    EXCLUDED_PATHS = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/v1/auth/login",
        "/v1/auth/refresh",
    }
    
    async def dispatch(self, request: Request, call_next: Callable):
        # Skip if no API key is configured
        if not PACT_API_KEY:
            return await call_next(request)
        
        # Skip excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)
        
        # Skip visualization (uses session/JWT)
        if request.url.path.startswith("/visualize"):
            return await call_next(request)
        
        # Check for API key in various locations
        api_key = self._extract_api_key(request)
        
        if not api_key or not secrets.compare_digest(api_key, PACT_API_KEY):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or missing API key"},
            )
        
        return await call_next(request)
    
    def _extract_api_key(self, request: Request) -> str | None:
        """Extract API key from request headers, query params, or cookies."""
        # Header: X-API-Key
        if api_key := request.headers.get("X-API-Key"):
            return api_key
        
        # Header: Authorization: Bearer <key>
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        
        # Query param
        if api_key := request.query_params.get("api_key"):
            return api_key
        if api_key := request.query_params.get("key"):
            return api_key
        
        # Cookie
        if api_key := request.cookies.get("pact_api_key"):
            return api_key
        
        return None


# =============================================================================
# Add Middleware (order matters - first added = last executed)
# =============================================================================

# CORS - must be first
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_allow_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

# Trusted hosts (prevent host header attacks)
trusted_hosts = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
if "*" not in trusted_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)

# Custom middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(LegacyAPIKeyMiddleware)


# =============================================================================
# Routes
# =============================================================================

@app.get("/", tags=["root"])
def home():
    """Root endpoint."""
    return {
        "name": "PACT Compliance Engine",
        "version": "2.0.0",
        "docs": "/docs",
        "dashboard": "/visualize/",
    }


@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    from datetime import datetime, timezone
    from sqlalchemy import text
    from app.core.database import engine
    
    # Check database connection
    db_status = "healthy"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "database": db_status,
    }


# Include API routers
app.include_router(api_router, prefix="/v1")

# Visualization dashboard
app.include_router(visualize.router, prefix="/visualize", tags=["visualization"])


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to prevent information leakage."""
    import traceback
    
    # Log the full error
    request_id = getattr(request.state, "request_id", "unknown")
    print(f"[{request_id}] Unhandled exception: {exc}")
    if os.getenv("DEBUG", "false").lower() == "true":
        traceback.print_exc()
    
    # Return sanitized error to client
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal error occurred",
            "request_id": request_id,
        },
    )


# =============================================================================
# Development Server
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
