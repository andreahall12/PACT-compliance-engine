"""
Scans endpoint for assessment history.

Provides list of past scans and their summaries.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel

from fastapi import APIRouter, Depends, Query, HTTPException, status

from app.core.store import db
from app.models.user import User
from app.auth.dependencies import require_permission

router = APIRouter()


class ScanSummary(BaseModel):
    """Summary of a single scan."""
    scan_id: str
    timestamp: str
    total_checks: int
    pass_count: int
    fail_count: int
    compliance_rate: float
    systems_affected: List[str]


class ScanListResponse(BaseModel):
    """List of scans with pagination."""
    scans: List[ScanSummary]
    total: int


class ScanDetail(BaseModel):
    """Detailed scan results."""
    scan_id: str
    timestamp: str
    total_checks: int
    pass_count: int
    fail_count: int
    compliance_rate: float
    findings: List[Dict[str, Any]]
    systems: Dict[str, Dict[str, int]]
    controls: Dict[str, Dict[str, int]]


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(20, ge=1, le=100, description="Number of scans to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(require_permission("compliance.read")),
):
    """
    List recent scans with summary statistics.
    
    Each scan represents a point-in-time compliance assessment.
    Named graphs in the TriG store correspond to individual scans.
    """
    # Query for all named graphs (scans) with their timestamps
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT DISTINCT ?g 
           (MIN(?time) AS ?scanTime)
           (COUNT(DISTINCT ?assess) AS ?totalChecks)
           (SUM(IF(?verdict = "PASS", 1, 0)) AS ?passCount)
           (SUM(IF(?verdict = "FAIL", 1, 0)) AS ?failCount)
           (GROUP_CONCAT(DISTINCT ?systemName; separator="|") AS ?systems)
    WHERE {
        GRAPH ?g {
            ?assess a pact:ComplianceAssessment ;
                    pact:hasVerdict ?verdict ;
                    pact:generatedAt ?time .
            
            OPTIONAL {
                ?assess pact:evaluatedEvidence ?ev .
                ?system pact:hasComponent ?ev ;
                        rdfs:label ?systemName .
            }
        }
    }
    GROUP BY ?g
    ORDER BY DESC(?scanTime)
    """
    
    scans = []
    try:
        results = list(db.query(query))
        
        for row in results:
            scan_id = str(row.g) if row.g else ""
            total = int(row.totalChecks) if row.totalChecks else 0
            passes = int(row.passCount) if row.passCount else 0
            fails = int(row.failCount) if row.failCount else 0
            systems_str = str(row.systems) if row.systems else ""
            systems = [s for s in systems_str.split("|") if s] if systems_str else []
            
            compliance_rate = (passes / total * 100) if total > 0 else 0.0
            
            scans.append(ScanSummary(
                scan_id=scan_id,
                timestamp=str(row.scanTime) if row.scanTime else "",
                total_checks=total,
                pass_count=passes,
                fail_count=fails,
                compliance_rate=round(compliance_rate, 2),
                systems_affected=systems[:10],  # Limit systems list
            ))
    except Exception as e:
        # If query fails, return empty list
        pass
    
    # Apply pagination
    total = len(scans)
    scans = scans[offset:offset + limit]
    
    return ScanListResponse(scans=scans, total=total)


@router.get("/{scan_id:path}", response_model=ScanDetail)
async def get_scan_detail(
    scan_id: str,
    current_user: User = Depends(require_permission("compliance.read")),
):
    """
    Get detailed results for a specific scan.
    
    Returns all findings, grouped by system and control.
    """
    # Query for scan details
    query = f"""
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
    
    SELECT ?verdict ?time ?controlName ?systemName ?asset ?evidenceLink
    WHERE {{
        GRAPH <{scan_id}> {{
            ?assess a pact:ComplianceAssessment ;
                    pact:hasVerdict ?verdict ;
                    pact:validatesControl ?control ;
                    pact:generatedAt ?time .
            
            ?control rdfs:label ?controlName .
            
            OPTIONAL {{
                ?assess pact:evaluatedEvidence ?ev .
                ?ev pact:evidenceSourceUrl ?evidenceLink .
                
                ?system pact:hasComponent ?ev ;
                        rdfs:label ?systemName .
                
                OPTIONAL {{ ?ev uco-obs:fileName ?asset }}
                OPTIONAL {{ ?ev uco-obs:destinationPort ?asset }}
            }}
        }}
    }}
    ORDER BY ?controlName
    """
    
    findings = []
    systems_stats: Dict[str, Dict[str, int]] = {}
    controls_stats: Dict[str, Dict[str, int]] = {}
    pass_count = 0
    fail_count = 0
    scan_time = None
    
    try:
        results = db.query(query)
        
        for row in results:
            verdict = str(row.verdict) if row.verdict else "UNKNOWN"
            control = str(row.controlName) if row.controlName else "Unknown"
            system = str(row.systemName) if row.systemName else "Unknown"
            
            if not scan_time and row.time:
                scan_time = str(row.time)
            
            # Count verdicts
            if verdict == "PASS":
                pass_count += 1
            elif verdict == "FAIL":
                fail_count += 1
            
            # Track by system
            if system not in systems_stats:
                systems_stats[system] = {"pass": 0, "fail": 0}
            if verdict == "PASS":
                systems_stats[system]["pass"] += 1
            elif verdict == "FAIL":
                systems_stats[system]["fail"] += 1
            
            # Track by control
            if control not in controls_stats:
                controls_stats[control] = {"pass": 0, "fail": 0}
            if verdict == "PASS":
                controls_stats[control]["pass"] += 1
            elif verdict == "FAIL":
                controls_stats[control]["fail"] += 1
            
            findings.append({
                "verdict": verdict,
                "control": control,
                "system": system,
                "asset": str(row.asset) if row.asset else None,
                "evidence_link": str(row.evidenceLink) if row.evidenceLink else None,
                "timestamp": str(row.time) if row.time else None,
            })
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found or query failed: {str(e)}",
        )
    
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or contains no assessments",
        )
    
    total = pass_count + fail_count
    compliance_rate = (pass_count / total * 100) if total > 0 else 0.0
    
    return ScanDetail(
        scan_id=scan_id,
        timestamp=scan_time or "",
        total_checks=total,
        pass_count=pass_count,
        fail_count=fail_count,
        compliance_rate=round(compliance_rate, 2),
        findings=findings,
        systems=systems_stats,
        controls=controls_stats,
    )


@router.get("/trends/summary")
async def get_scan_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    current_user: User = Depends(require_permission("compliance.read")),
):
    """
    Get compliance trend data for charting.
    
    Returns aggregated stats over time for trend visualization.
    """
    scans_response = await list_scans(limit=100, offset=0, current_user=current_user)
    
    # Calculate trends
    if not scans_response.scans:
        return {
            "period_days": days,
            "total_scans": 0,
            "avg_compliance_rate": 0.0,
            "trend": "stable",
            "data_points": [],
        }
    
    # Simple trend calculation
    compliance_rates = [s.compliance_rate for s in scans_response.scans]
    avg_rate = sum(compliance_rates) / len(compliance_rates) if compliance_rates else 0
    
    # Determine trend direction
    if len(compliance_rates) >= 2:
        recent_avg = sum(compliance_rates[:len(compliance_rates)//2]) / (len(compliance_rates)//2)
        older_avg = sum(compliance_rates[len(compliance_rates)//2:]) / (len(compliance_rates) - len(compliance_rates)//2)
        
        if recent_avg > older_avg + 5:
            trend = "improving"
        elif recent_avg < older_avg - 5:
            trend = "declining"
        else:
            trend = "stable"
    else:
        trend = "stable"
    
    return {
        "period_days": days,
        "total_scans": len(scans_response.scans),
        "avg_compliance_rate": round(avg_rate, 2),
        "trend": trend,
        "data_points": [
            {"timestamp": s.timestamp, "compliance_rate": s.compliance_rate}
            for s in scans_response.scans[:50]  # Limit data points
        ],
    }

