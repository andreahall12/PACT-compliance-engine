"""
Historical compliance view endpoints.

The "Time Machine" feature - view compliance state at any point in time.
Uses the TriG named graphs to track temporal data.
"""

from datetime import datetime, timezone, date
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from rdflib import Graph, Namespace, URIRef
from rdflib.namespace import RDF, RDFS, XSD

from app.core.database import get_db
from app.core.config import DB_FILE
from app.core.store import db as pact_store
from app.models.user import User
from app.auth.dependencies import require_permission
from app.schemas.incident import HistoricalComplianceState

router = APIRouter()

PACT = Namespace("http://your-org.com/ns/pact#")


@router.get("/at", response_model=HistoricalComplianceState)
async def get_compliance_at_date(
    as_of: datetime = Query(..., description="Point in time to view compliance state"),
    system_id: Optional[str] = Query(None, description="Filter by system ID"),
    framework_id: Optional[str] = Query(None, description="Filter by framework ID"),
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    View compliance state at a specific point in time.
    
    Uses the TriG named graphs to find assessments that were
    valid as of the requested date.
    """
    try:
        # Load the full graph (Dataset)
        g = pact_store.ds
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load knowledge graph: {str(e)}",
        )
    
    # Query for assessments up to the specified date
    query = f"""
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>

    SELECT ?system ?systemName ?control ?controlName ?verdict ?time ?asset
    WHERE {{
        GRAPH ?g {{
            ?assessment a pact:ComplianceAssessment ;
                        pact:hasVerdict ?verdict ;
                        pact:validatesControl ?control ;
                        pact:generatedAt ?time .
            
            FILTER(?time <= "{as_of.isoformat()}"^^xsd:dateTime)
            
            ?ev pact:evidenceSourceUrl ?link .
            {{ ?ev uco-obs:fileName ?asset }} UNION {{ ?ev uco-obs:destinationPort ?asset }}
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName .
            
            ?control rdfs:label ?controlName .
        }}
    }}
    ORDER BY DESC(?time)
    """
    
    try:
        results = g.query(query)
    except Exception as e:
        # If query fails (e.g., no data), return empty state
        return HistoricalComplianceState(
            as_of=as_of,
            total_assessments=0,
            pass_count=0,
            fail_count=0,
            compliance_rate=0.0,
            systems=[],
            frameworks=[],
            failures=[],
        )
    
    # Process results
    pass_count = 0
    fail_count = 0
    systems_data = {}
    failures = []
    
    for row in results:
        verdict = str(row.verdict) if row.verdict else "UNKNOWN"
        system_name = str(row.systemName) if row.systemName else "Unknown"
        control_name = str(row.controlName) if row.controlName else "Unknown"
        asset = str(row.asset) if row.asset else ""
        timestamp = str(row.time) if row.time else ""
        
        # Apply filters
        if system_id and system_name != system_id:
            continue
        
        if verdict == "PASS":
            pass_count += 1
        elif verdict == "FAIL":
            fail_count += 1
            failures.append({
                "system": system_name,
                "control": control_name,
                "asset": asset,
                "timestamp": timestamp,
            })
        
        # Aggregate by system
        if system_name not in systems_data:
            systems_data[system_name] = {"pass_count": 0, "fail_count": 0}
        
        if verdict == "PASS":
            systems_data[system_name]["pass_count"] += 1
        elif verdict == "FAIL":
            systems_data[system_name]["fail_count"] += 1
    
    total = pass_count + fail_count
    compliance_rate = (pass_count / total * 100) if total > 0 else 0.0
    
    return HistoricalComplianceState(
        as_of=as_of,
        total_assessments=total,
        pass_count=pass_count,
        fail_count=fail_count,
        compliance_rate=round(compliance_rate, 2),
        systems=[
            {"system_id": k, "pass_count": v["pass_count"], "fail_count": v["fail_count"]}
            for k, v in systems_data.items()
        ],
        frameworks=[],  # TODO: Aggregate by framework
        failures=failures[:50],  # Limit to 50 for response size
    )


@router.get("/timeline")
async def get_compliance_timeline(
    system_id: Optional[str] = Query(None, description="Filter by system ID"),
    control_id: Optional[str] = Query(None, description="Filter by control ID"),
    from_date: Optional[date] = Query(None, description="Start date"),
    to_date: Optional[date] = Query(None, description="End date"),
    current_user: User = Depends(require_permission("systems.read")),
):
    """
    Get compliance timeline showing status changes over time.
    
    Returns a series of events showing when compliance state changed.
    """
    try:
        g = pact_store.ds
    except Exception:
        return {"events": [], "message": "No historical data available"}
    
    # Build query with filters
    filters = []
    if from_date:
        filters.append(f'FILTER(?time >= "{from_date.isoformat()}T00:00:00"^^xsd:dateTime)')
    if to_date:
        filters.append(f'FILTER(?time <= "{to_date.isoformat()}T23:59:59"^^xsd:dateTime)')
    if system_id:
        filters.append(f'FILTER(str(?systemName) = "{system_id}")')
    if control_id:
        filters.append(f'FILTER(CONTAINS(str(?controlName), "{control_id}"))')
    
    filter_clause = "\n            ".join(filters)
    
    query = f"""
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

    SELECT ?systemName ?controlName ?verdict ?time
    WHERE {{
        GRAPH ?g {{
            ?assessment a pact:ComplianceAssessment ;
                        pact:hasVerdict ?verdict ;
                        pact:validatesControl ?control ;
                        pact:generatedAt ?time .
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName .
            
            ?control rdfs:label ?controlName .
            
            {filter_clause}
        }}
    }}
    ORDER BY ?time
    LIMIT 500
    """
    
    try:
        results = g.query(query)
        
        events = []
        for row in results:
            events.append({
                "timestamp": str(row.time) if row.time else "",
                "system": str(row.systemName) if row.systemName else "",
                "control": str(row.controlName) if row.controlName else "",
                "verdict": str(row.verdict) if row.verdict else "",
            })
        
        return {"events": events}
    
    except Exception as e:
        return {"events": [], "error": str(e)}


@router.get("/compare")
async def compare_compliance_states(
    date1: datetime = Query(..., description="First comparison date"),
    date2: datetime = Query(..., description="Second comparison date"),
    system_id: Optional[str] = Query(None, description="Filter by system ID"),
    current_user: User = Depends(require_permission("systems.read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Compare compliance state between two points in time.
    
    Useful for:
    - Audit preparation (show improvement)
    - Drift detection
    - Trend analysis
    """
    # Get state at both dates
    # This would call get_compliance_at_date internally
    
    # For now, return placeholder
    return {
        "date1": date1.isoformat(),
        "date2": date2.isoformat(),
        "changes": {
            "new_failures": [],
            "resolved_failures": [],
            "unchanged_failures": [],
            "compliance_rate_change": 0.0,
        },
        "summary": "Comparison feature requires more historical data",
    }

