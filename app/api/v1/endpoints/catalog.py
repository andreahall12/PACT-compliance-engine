"""
Catalog endpoint for dynamic UI filters.

Provides lists of available systems, frameworks, controls, and other
entities that the UI can use to populate filter dropdowns dynamically.
"""

from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.store import db
from app.models.user import User
from app.auth.dependencies import get_current_active_user

router = APIRouter()


class SystemInfo(BaseModel):
    """System summary for catalog."""
    id: str
    name: str
    status: Optional[str] = None
    failure_count: int = 0
    pass_count: int = 0


class FrameworkInfo(BaseModel):
    """Framework/control summary."""
    id: str
    name: str
    control_count: int = 0


class ControlInfo(BaseModel):
    """Individual control info."""
    id: str
    name: str
    framework: Optional[str] = None
    mapped_requirements: List[str] = []


class CatalogResponse(BaseModel):
    """Complete catalog for UI filters."""
    systems: List[SystemInfo]
    frameworks: List[FrameworkInfo]
    controls: List[ControlInfo]
    event_types: List[str]
    verdicts: List[str]
    last_updated: str


@router.get("", response_model=CatalogResponse)
async def get_catalog(
    current_user: User = Depends(get_current_active_user),
):
    """
    Get catalog of all available filter options.
    
    Returns lists of:
    - Systems (from context graph and assessments)
    - Frameworks and controls
    - Event types
    - Verdict options
    
    The UI should use this to populate filter dropdowns dynamically
    instead of hard-coding values.
    """
    # Query for systems from the knowledge graph
    systems_query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT DISTINCT ?system ?systemName 
           (COUNT(DISTINCT ?failAssess) AS ?failCount)
           (COUNT(DISTINCT ?passAssess) AS ?passCount)
    WHERE {
        ?system a pact:System ;
                rdfs:label ?systemName .
        
        OPTIONAL {
            GRAPH ?g1 {
                ?failAssess pact:hasVerdict "FAIL" .
                ?system pact:hasComponent ?ev1 .
                ?failAssess pact:evaluatedEvidence ?ev1 .
            }
        }
        
        OPTIONAL {
            GRAPH ?g2 {
                ?passAssess pact:hasVerdict "PASS" .
                ?system pact:hasComponent ?ev2 .
                ?passAssess pact:evaluatedEvidence ?ev2 .
            }
        }
    }
    GROUP BY ?system ?systemName
    ORDER BY ?systemName
    """
    
    systems = []
    try:
        results = db.query(systems_query)
        for row in results:
            systems.append(SystemInfo(
                id=str(row.system).split("#")[-1] if row.system else "",
                name=str(row.systemName) if row.systemName else "Unknown",
                failure_count=int(row.failCount) if row.failCount else 0,
                pass_count=int(row.passCount) if row.passCount else 0,
            ))
    except Exception:
        # Fallback to basic system query
        fallback_query = """
        PREFIX pact: <http://your-org.com/ns/pact#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        
        SELECT DISTINCT ?system ?systemName
        WHERE {
            ?system a pact:System ;
                    rdfs:label ?systemName .
        }
        ORDER BY ?systemName
        """
        try:
            results = db.query(fallback_query)
            for row in results:
                systems.append(SystemInfo(
                    id=str(row.system).split("#")[-1] if row.system else "",
                    name=str(row.systemName) if row.systemName else "Unknown",
                ))
        except Exception:
            pass

    # Query for controls
    controls_query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT DISTINCT ?control ?controlName (GROUP_CONCAT(?req; separator=", ") AS ?requirements)
    WHERE {
        ?control a pact:Control ;
                 rdfs:label ?controlName .
        OPTIONAL { ?control pact:satisfiesRequirement ?req }
    }
    GROUP BY ?control ?controlName
    ORDER BY ?controlName
    """
    
    controls = []
    frameworks_set = set()
    
    try:
        results = db.query(controls_query)
        for row in results:
            control_name = str(row.controlName) if row.controlName else ""
            requirements = str(row.requirements).split(", ") if row.requirements else []
            
            # Extract framework from control name (e.g., "NIST AC-3" -> "NIST")
            framework = control_name.split(" ")[0] if " " in control_name else "Custom"
            frameworks_set.add(framework)
            
            # Also add mapped frameworks
            for req in requirements:
                if req:
                    fw = req.split(" ")[0]
                    frameworks_set.add(fw)
            
            controls.append(ControlInfo(
                id=str(row.control).split("#")[-1] if row.control else "",
                name=control_name,
                framework=framework,
                mapped_requirements=[r for r in requirements if r],
            ))
    except Exception:
        pass

    # Build frameworks list from controls
    frameworks = [
        FrameworkInfo(
            id=fw.lower().replace(" ", "-"),
            name=fw,
            control_count=len([c for c in controls if c.framework == fw]),
        )
        for fw in sorted(frameworks_set) if fw
    ]
    
    # Standard event types and verdicts
    event_types = ["file_access", "network_connection", "authentication", "api_call", "config_change"]
    verdicts = ["PASS", "FAIL"]

    return CatalogResponse(
        systems=systems,
        frameworks=frameworks,
        controls=controls,
        event_types=event_types,
        verdicts=verdicts,
        last_updated=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/systems", response_model=List[SystemInfo])
async def get_systems_catalog(
    current_user: User = Depends(get_current_active_user),
):
    """Get just the systems list for filter dropdowns."""
    catalog = await get_catalog(current_user)
    return catalog.systems


@router.get("/frameworks", response_model=List[FrameworkInfo])
async def get_frameworks_catalog(
    current_user: User = Depends(get_current_active_user),
):
    """Get just the frameworks list for filter dropdowns."""
    catalog = await get_catalog(current_user)
    return catalog.frameworks


@router.get("/controls", response_model=List[ControlInfo])
async def get_controls_catalog(
    framework: Optional[str] = Query(None, description="Filter by framework"),
    current_user: User = Depends(get_current_active_user),
):
    """Get controls list, optionally filtered by framework."""
    catalog = await get_catalog(current_user)
    
    if framework:
        return [c for c in catalog.controls if c.framework and c.framework.lower() == framework.lower()]
    
    return catalog.controls

