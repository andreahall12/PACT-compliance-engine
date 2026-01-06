"""
User and Role models for RBAC.

Security considerations:
- Passwords are hashed with Argon2id (memory-hard, side-channel resistant)
- API tokens are hashed before storage
- Email is indexed but not unique (allows soft delete scenarios)
- All timestamps use UTC
"""

import secrets
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, List
from sqlalchemy import (
    String, Boolean, DateTime, ForeignKey, Enum, Text, Table, Column, Integer
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.database import Base


# Password hasher with secure defaults
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB memory usage
    parallelism=4,      # Number of parallel threads
    hash_len=32,        # Length of the hash
    salt_len=16,        # Length of the salt
)


class UserRole(str, PyEnum):
    """
    User roles with hierarchical permissions.
    Ordered from most to least privileged for easy comparison.
    """
    ADMIN = "admin"
    COMPLIANCE_OFFICER = "compliance_officer"
    INTERNAL_AUDITOR = "internal_auditor"
    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"
    SYSTEM_OWNER = "system_owner"
    PRODUCT_MANAGER = "product_manager"
    CISO = "ciso"
    EXTERNAL_AUDITOR = "external_auditor"


# Association table for user-team membership (many-to-many)
user_teams = Table(
    "user_teams",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("team_id", Integer, ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True),
)

# Association table for user-system ownership (many-to-many)
user_systems = Table(
    "user_systems",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("system_id", Integer, ForeignKey("systems.id", ondelete="CASCADE"), primary_key=True),
)


class Team(Base):
    """Team/department for organizational grouping."""
    
    __tablename__ = "teams"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
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
    members: Mapped[List["User"]] = relationship(
        "User",
        secondary=user_teams,
        back_populates="teams"
    )
    
    def __repr__(self) -> str:
        return f"<Team {self.name}>"


class User(Base):
    """
    User model with secure authentication.
    
    Security features:
    - Argon2id password hashing
    - Account lockout after failed attempts
    - API token hashing
    - Soft delete support
    """
    
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    
    # Authentication
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Profile
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False, default=UserRole.DEVELOPER)
    
    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Security: Account lockout
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # API Token (hashed)
    api_token_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    api_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Notification preferences (JSON stored as text)
    notification_prefs: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
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
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Soft delete
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    teams: Mapped[List["Team"]] = relationship(
        "Team",
        secondary=user_teams,
        back_populates="members"
    )
    
    # Audit trail
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")
    
    def __repr__(self) -> str:
        return f"<User {self.email}>"
    
    def set_password(self, password: str) -> None:
        """Hash and set password using Argon2id."""
        self.password_hash = ph.hash(password)
    
    def verify_password(self, password: str) -> bool:
        """
        Verify password against stored hash.
        Returns False if password is wrong or needs rehashing.
        """
        try:
            ph.verify(self.password_hash, password)
            # Check if rehash is needed (parameters changed)
            if ph.check_needs_rehash(self.password_hash):
                self.set_password(password)
            return True
        except VerifyMismatchError:
            return False
    
    def is_locked(self) -> bool:
        """Check if account is locked due to failed login attempts."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until
    
    def record_failed_login(self) -> None:
        """Record a failed login attempt. Lock account after 5 failures."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            # Lock for 15 minutes
            from datetime import timedelta
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    def record_successful_login(self) -> None:
        """Reset failed login counter on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)
    
    def generate_api_token(self) -> str:
        """
        Generate a new API token.
        Returns the raw token (only shown once).
        Stores the hashed version.
        """
        from datetime import timedelta
        import hashlib
        
        # Generate a secure random token
        raw_token = secrets.token_urlsafe(32)
        
        # Hash it for storage (SHA-256 is fine for tokens, not passwords)
        self.api_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        self.api_token_expires = datetime.now(timezone.utc) + timedelta(days=90)
        
        return raw_token
    
    def verify_api_token(self, token: str) -> bool:
        """Verify an API token against stored hash."""
        import hashlib
        
        if not self.api_token_hash or not self.api_token_expires:
            return False
        
        if datetime.now(timezone.utc) > self.api_token_expires:
            return False
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return secrets.compare_digest(token_hash, self.api_token_hash)
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission based on their role."""
        return permission in ROLE_PERMISSIONS.get(self.role, set())
    
    def can_access_system(self, system_id: int) -> bool:
        """
        Check if user can access a specific system.
        Admin/Compliance Officer/CISO can access all.
        System owners can access their assigned systems.
        """
        if self.role in {UserRole.ADMIN, UserRole.COMPLIANCE_OFFICER, UserRole.CISO}:
            return True
        
        # Check if user owns this system
        return any(s.id == system_id for s in getattr(self, 'owned_systems', []))


# Role-based permissions mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: {
        "users.create", "users.read", "users.update", "users.delete",
        "systems.create", "systems.read", "systems.update", "systems.delete",
        "products.create", "products.read", "products.update", "products.delete",
        "policies.create", "policies.read", "policies.update", "policies.delete",
        "documents.create", "documents.read", "documents.update", "documents.delete",
        "incidents.create", "incidents.read", "incidents.update", "incidents.delete",
        "vendors.create", "vendors.read", "vendors.update", "vendors.delete",
        "schedules.create", "schedules.read", "schedules.update", "schedules.delete", "schedules.execute",
        "notifications.manage", "notifications.send",
        "compliance.read",
        "audit.read",
        "settings.update",
        "ingest.execute",
        "reports.generate",
        "ai.chat",
    },
    UserRole.COMPLIANCE_OFFICER: {
        "users.read",
        "systems.create", "systems.read", "systems.update",
        "products.create", "products.read", "products.update",
        "policies.create", "policies.read", "policies.update", "policies.delete",
        "documents.create", "documents.read", "documents.update", "documents.delete",
        "incidents.read", "incidents.update",
        "vendors.create", "vendors.read", "vendors.update",
        "schedules.create", "schedules.read", "schedules.update", "schedules.execute",
        "notifications.manage",
        "compliance.read",
        "audit.read",
        "ingest.execute",
        "reports.generate",
        "ai.chat",
        "exceptions.create", "exceptions.approve",
    },
    UserRole.INTERNAL_AUDITOR: {
        "users.read",
        "systems.read",
        "products.read",
        "policies.read",
        "documents.create", "documents.read", "documents.update",
        "incidents.read",
        "vendors.read",
        "schedules.read",
        "compliance.read",
        "audit.read",
        "reports.generate",
        "ai.chat",
        "evidence.request",
    },
    UserRole.SECURITY_ENGINEER: {
        "systems.read",
        "products.read",
        "policies.read",
        "documents.create", "documents.read",
        "incidents.create", "incidents.read", "incidents.update",
        "vendors.read",
        "schedules.read",
        "compliance.read",
        "ingest.execute",
        "reports.generate",
        "ai.chat",
        "remediation.execute",
        "exceptions.request",
    },
    UserRole.DEVELOPER: {
        "systems.read",
        "policies.read",
        "documents.read",
        "compliance.read",
        "ai.chat",
        "remediation.execute",
    },
    UserRole.SYSTEM_OWNER: {
        "systems.read", "systems.update",  # Own systems only
        "documents.create", "documents.read",
        "incidents.read",
        "compliance.read",
        "reports.generate",
        "ai.chat",
        "exceptions.request",
    },
    UserRole.PRODUCT_MANAGER: {
        "systems.read",
        "products.read", "products.update",  # Own products only
        "documents.read",
        "compliance.read",
        "reports.generate",
        "ai.chat",
        "releases.approve",
    },
    UserRole.CISO: {
        "users.read",
        "systems.read",
        "products.read",
        "policies.read",
        "documents.read",
        "incidents.read",
        "vendors.read",
        "schedules.read",
        "compliance.read",
        "audit.read",
        "reports.generate",
        "ai.chat",
    },
    UserRole.EXTERNAL_AUDITOR: {
        "systems.read",  # Scoped to audit
        "policies.read",
        "documents.read",  # Scoped to audit
        "compliance.read",
        "audit.read",
        "reports.generate",
        "evidence.request",
    },
}


# Import for type hints (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.models.audit import AuditLog

