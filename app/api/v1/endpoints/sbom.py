"""
SBOM (Software Bill of Materials) Integration endpoints.

Manages SBOM uploads, parsing, and vulnerability correlation.
Supports CycloneDX and SPDX formats.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.config import DATA_DIR
from app.models.user import User
from app.models.system import System
from app.auth.dependencies import require_permission

router = APIRouter()

# SBOM storage directory
SBOM_DIR = DATA_DIR / "sbom"


class SBOMComponent(BaseModel):
    """A component/package from an SBOM."""
    name: str
    version: str
    type: str = "library"  # library, framework, application, os, device
    purl: Optional[str] = None  # Package URL
    cpe: Optional[str] = None   # Common Platform Enumeration
    licenses: List[str] = []
    supplier: Optional[str] = None


class SBOMVulnerability(BaseModel):
    """A vulnerability affecting an SBOM component."""
    id: str  # CVE-XXXX-XXXXX
    severity: str  # critical, high, medium, low
    cvss_score: Optional[float] = None
    affected_component: str
    affected_versions: str
    fixed_version: Optional[str] = None
    description: Optional[str] = None
    references: List[str] = []


class SBOMSummary(BaseModel):
    """Summary of an SBOM for a system."""
    system_id: int
    system_name: str
    sbom_format: str  # cyclonedx, spdx
    total_components: int
    components_by_type: Dict[str, int]
    license_summary: Dict[str, int]
    last_updated: datetime
    vulnerability_summary: Optional[Dict[str, int]] = None


class SBOMUploadResponse(BaseModel):
    """Response from SBOM upload."""
    status: str
    system_id: int
    sbom_id: str
    format: str
    components_parsed: int
    warnings: List[str] = []


class VulnerabilityScanResult(BaseModel):
    """Result of vulnerability scan against SBOM."""
    system_id: int
    system_name: str
    scan_time: datetime
    total_vulnerabilities: int
    by_severity: Dict[str, int]
    vulnerabilities: List[SBOMVulnerability]


def detect_sbom_format(content: str) -> str:
    """Detect SBOM format from content."""
    try:
        data = json.loads(content)
        if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
            return "cyclonedx"
        if "spdxVersion" in data:
            return "spdx"
    except json.JSONDecodeError:
        # Could be XML
        if "CycloneDX" in content:
            return "cyclonedx-xml"
        if "SPDX" in content:
            return "spdx-xml"
    return "unknown"


def parse_cyclonedx(content: str) -> List[SBOMComponent]:
    """Parse CycloneDX SBOM."""
    components = []
    try:
        data = json.loads(content)
        for comp in data.get("components", []):
            components.append(SBOMComponent(
                name=comp.get("name", "unknown"),
                version=comp.get("version", "unknown"),
                type=comp.get("type", "library"),
                purl=comp.get("purl"),
                cpe=comp.get("cpe"),
                licenses=[l.get("license", {}).get("id", "") for l in comp.get("licenses", []) if l.get("license")],
                supplier=comp.get("supplier", {}).get("name") if comp.get("supplier") else None,
            ))
    except Exception:
        pass
    return components


def parse_spdx(content: str) -> List[SBOMComponent]:
    """Parse SPDX SBOM."""
    components = []
    try:
        data = json.loads(content)
        for pkg in data.get("packages", []):
            components.append(SBOMComponent(
                name=pkg.get("name", "unknown"),
                version=pkg.get("versionInfo", "unknown"),
                type="library",
                purl=next((ref.get("referenceLocator") for ref in pkg.get("externalRefs", []) 
                          if ref.get("referenceType") == "purl"), None),
                licenses=[pkg.get("licenseDeclared", "")],
                supplier=pkg.get("supplier"),
            ))
    except Exception:
        pass
    return components


@router.post("/upload/{system_id}", response_model=SBOMUploadResponse)
async def upload_sbom(
    system_id: int,
    sbom_file: UploadFile = File(..., description="SBOM file (CycloneDX or SPDX JSON)"),
    current_user: User = Depends(require_permission("systems.update")),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload an SBOM for a system.
    
    Supports:
    - CycloneDX JSON
    - SPDX JSON
    
    The SBOM will be parsed and components extracted for vulnerability tracking.
    """
    # Verify system exists
    result = await db.execute(
        select(System).where(System.id == system_id)
    )
    system = result.scalar_one_or_none()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found",
        )
    
    # Read and parse SBOM
    content = await sbom_file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SBOM file must be valid UTF-8 text",
        )
    
    # Detect format
    sbom_format = detect_sbom_format(content_str)
    if sbom_format == "unknown":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown SBOM format. Supported: CycloneDX JSON, SPDX JSON",
        )
    
    # Parse components
    if sbom_format == "cyclonedx":
        components = parse_cyclonedx(content_str)
    elif sbom_format == "spdx":
        components = parse_spdx(content_str)
    else:
        components = []
    
    # Save SBOM file
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    sbom_id = str(uuid.uuid4())
    file_path = SBOM_DIR / f"{system_id}_{sbom_id}.json"
    
    with open(file_path, 'w') as f:
        f.write(content_str)
    
    # Update system with SBOM reference
    system.sbom_url = str(file_path)
    await db.commit()
    
    warnings = []
    if len(components) == 0:
        warnings.append("No components found in SBOM")
    
    return SBOMUploadResponse(
        status="success",
        system_id=system_id,
        sbom_id=sbom_id,
        format=sbom_format,
        components_parsed=len(components),
        warnings=warnings,
    )


@router.get("/{system_id}", response_model=SBOMSummary)
async def get_sbom_summary(
    system_id: int,
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get SBOM summary for a system."""
    result = await db.execute(
        select(System).where(System.id == system_id)
    )
    system = result.scalar_one_or_none()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found",
        )
    
    if not system.sbom_url or not Path(system.sbom_url).exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No SBOM uploaded for this system",
        )
    
    # Load and parse SBOM
    with open(system.sbom_url, 'r') as f:
        content = f.read()
    
    sbom_format = detect_sbom_format(content)
    
    if sbom_format == "cyclonedx":
        components = parse_cyclonedx(content)
    elif sbom_format == "spdx":
        components = parse_spdx(content)
    else:
        components = []
    
    # Calculate summaries
    components_by_type = {}
    license_summary = {}
    
    for comp in components:
        comp_type = comp.type or "library"
        components_by_type[comp_type] = components_by_type.get(comp_type, 0) + 1
        
        for lic in comp.licenses:
            if lic:
                license_summary[lic] = license_summary.get(lic, 0) + 1
    
    return SBOMSummary(
        system_id=system.id,
        system_name=system.display_name,
        sbom_format=sbom_format,
        total_components=len(components),
        components_by_type=components_by_type,
        license_summary=license_summary,
        last_updated=datetime.fromtimestamp(
            Path(system.sbom_url).stat().st_mtime, tz=timezone.utc
        ),
    )


@router.get("/{system_id}/components", response_model=List[SBOMComponent])
async def get_sbom_components(
    system_id: int,
    component_type: Optional[str] = Query(None, description="Filter by component type"),
    search: Optional[str] = Query(None, description="Search by name"),
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """Get all components from a system's SBOM."""
    result = await db.execute(
        select(System).where(System.id == system_id)
    )
    system = result.scalar_one_or_none()
    
    if not system or not system.sbom_url or not Path(system.sbom_url).exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No SBOM found for this system",
        )
    
    with open(system.sbom_url, 'r') as f:
        content = f.read()
    
    sbom_format = detect_sbom_format(content)
    
    if sbom_format == "cyclonedx":
        components = parse_cyclonedx(content)
    elif sbom_format == "spdx":
        components = parse_spdx(content)
    else:
        components = []
    
    # Apply filters
    if component_type:
        components = [c for c in components if c.type == component_type]
    
    if search:
        search_lower = search.lower()
        components = [c for c in components if search_lower in c.name.lower()]
    
    return components


@router.get("/{system_id}/vulnerabilities", response_model=VulnerabilityScanResult)
async def scan_vulnerabilities(
    system_id: int,
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Scan SBOM components for known vulnerabilities.
    
    Note: In production, this would integrate with vulnerability databases
    like NVD, OSV, or commercial services. This is a mock implementation.
    """
    result = await db.execute(
        select(System).where(System.id == system_id)
    )
    system = result.scalar_one_or_none()
    
    if not system or not system.sbom_url or not Path(system.sbom_url).exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No SBOM found for this system",
        )
    
    with open(system.sbom_url, 'r') as f:
        content = f.read()
    
    sbom_format = detect_sbom_format(content)
    
    if sbom_format == "cyclonedx":
        components = parse_cyclonedx(content)
    elif sbom_format == "spdx":
        components = parse_spdx(content)
    else:
        components = []
    
    # Mock vulnerability data
    # In production, query NVD/OSV APIs
    mock_vulnerabilities = []
    
    # Simulate finding vulnerabilities in common packages
    vulnerable_packages = {
        "log4j": ("CVE-2021-44228", "critical", 10.0, "2.17.0"),
        "spring-core": ("CVE-2022-22965", "critical", 9.8, "5.3.18"),
        "lodash": ("CVE-2021-23337", "high", 7.2, "4.17.21"),
        "axios": ("CVE-2021-3749", "medium", 5.3, "0.21.2"),
    }
    
    for comp in components:
        name_lower = comp.name.lower()
        for vuln_pkg, (cve, severity, cvss, fixed) in vulnerable_packages.items():
            if vuln_pkg in name_lower:
                mock_vulnerabilities.append(SBOMVulnerability(
                    id=cve,
                    severity=severity,
                    cvss_score=cvss,
                    affected_component=comp.name,
                    affected_versions=f"< {fixed}",
                    fixed_version=fixed,
                    description=f"Known vulnerability in {comp.name}",
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                ))
    
    # Count by severity
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in mock_vulnerabilities:
        if vuln.severity in by_severity:
            by_severity[vuln.severity] += 1
    
    return VulnerabilityScanResult(
        system_id=system.id,
        system_name=system.display_name,
        scan_time=datetime.now(timezone.utc),
        total_vulnerabilities=len(mock_vulnerabilities),
        by_severity=by_severity,
        vulnerabilities=mock_vulnerabilities,
    )


@router.get("/enterprise/summary")
async def get_enterprise_sbom_summary(
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get enterprise-wide SBOM and vulnerability summary.
    
    Aggregates data across all systems with SBOMs.
    """
    result = await db.execute(
        select(System).where(System.sbom_url.isnot(None))
    )
    systems = result.scalars().all()
    
    total_components = 0
    total_vulnerabilities = 0
    systems_with_sbom = 0
    all_components_by_type = {}
    
    for system in systems:
        if not system.sbom_url or not Path(system.sbom_url).exists():
            continue
        
        systems_with_sbom += 1
        
        with open(system.sbom_url, 'r') as f:
            content = f.read()
        
        sbom_format = detect_sbom_format(content)
        
        if sbom_format == "cyclonedx":
            components = parse_cyclonedx(content)
        elif sbom_format == "spdx":
            components = parse_spdx(content)
        else:
            components = []
        
        total_components += len(components)
        
        for comp in components:
            comp_type = comp.type or "library"
            all_components_by_type[comp_type] = all_components_by_type.get(comp_type, 0) + 1
    
    return {
        "systems_with_sbom": systems_with_sbom,
        "total_systems": len(systems),
        "total_components": total_components,
        "components_by_type": all_components_by_type,
        "coverage_percentage": round(systems_with_sbom / max(len(systems), 1) * 100, 2),
    }

