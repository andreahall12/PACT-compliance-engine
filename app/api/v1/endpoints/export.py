"""
Export endpoints for compliance reports.

Provides OSCAL and other standard format exports.
"""

import json
import datetime
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse

from app.core.store import db, PACT
from app.models.user import User
from app.auth.dependencies import require_permission

router = APIRouter()


def generate_oscal_from_store(
    system_filter: Optional[str] = None,
    framework_filter: Optional[str] = None,
) -> dict:
    """
    Generate OSCAL Assessment Results from the in-memory knowledge graph.
    
    Returns a NIST OSCAL 1.1.2 compliant JSON structure.
    """
    # Initialize OSCAL Structure (Security Assessment Report)
    oscal_data = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "PACT Automated Compliance Assessment",
                "last-modified": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "roles": [
                    {"id": "auditor", "title": "Automated Auditor (PACT)"},
                    {"id": "tool", "title": "PACT Compliance Engine"}
                ],
                "parties": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "type": "organization",
                        "name": "Your Organization"
                    }
                ]
            },
            "import-ap": {
                "href": "#",
                "remarks": "Assessment plan reference (if using ComplyTime)"
            },
            "results": []
        }
    }

    # Build SPARQL query with optional filters
    filter_clauses = []
    if system_filter:
        filter_clauses.append(f'FILTER(CONTAINS(LCASE(str(?systemName)), LCASE("{system_filter}")))')
    if framework_filter:
        filter_clauses.append(f'FILTER(CONTAINS(LCASE(str(?controlName)), LCASE("{framework_filter}")))')
    
    filter_string = "\n            ".join(filter_clauses)

    query = f"""
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
    
    SELECT ?systemName ?controlName ?verdict ?time ?evidenceLink ?asset
    WHERE {{
        GRAPH ?g {{
            ?assess pact:hasVerdict ?verdict ;
                    pact:validatesControl ?control ;
                    pact:evaluatedEvidence ?ev ;
                    pact:generatedAt ?time .
            
            ?ev pact:evidenceSourceUrl ?evidenceLink .
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName .
            
            ?control rdfs:label ?controlName .
            
            OPTIONAL {{ ?ev uco-obs:fileName ?asset }}
            OPTIONAL {{ ?ev uco-obs:destinationPort ?asset }}
            
            {filter_string}
        }}
    }}
    ORDER BY DESC(?time)
    """

    try:
        results = db.query(query)
    except Exception:
        results = []

    # Group by System for clearer reporting
    system_results = {}
    
    for row in results:
        sys_name = str(row.systemName) if row.systemName else "Unknown System"
        
        if sys_name not in system_results:
            system_results[sys_name] = {
                "uuid": str(uuid.uuid4()),
                "title": f"Assessment of {sys_name}",
                "description": "Automated continuous monitoring scan by PACT.",
                "start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "observations": [],
                "findings": []
            }

        # Create an OSCAL "Observation" for each finding
        observation = {
            "uuid": str(uuid.uuid4()),
            "description": f"Check for {row.controlName} on {row.asset if row.asset else 'Unknown Asset'}",
            "methods": ["TEST-AUTOMATED"],
            "types": ["finding"],
            "collected": str(row.time) if row.time else datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "relevant-evidence": [
                {
                    "href": str(row.evidenceLink) if row.evidenceLink else "#",
                    "description": "Raw Log / Technical Proof"
                }
            ],
            "subjects": [
                {
                    "type": "component",
                    "title": str(row.asset) if row.asset else "Unknown Component"
                }
            ]
        }

        verdict = str(row.verdict) if row.verdict else "UNKNOWN"
        
        if verdict == "FAIL":
            observation["title"] = f"FAILURE: {row.controlName}"
            observation["props"] = [{"name": "status", "value": "not-satisfied"}]
            
            # Add to findings for failures
            finding = {
                "uuid": str(uuid.uuid4()),
                "title": f"Non-Compliance: {row.controlName}",
                "description": f"Control {row.controlName} failed validation on {sys_name}",
                "target": {
                    "type": "objective-id",
                    "target-id": str(row.controlName).replace(" ", "-").lower(),
                    "status": {"state": "not-satisfied"}
                },
                "related-observations": [{"observation-uuid": observation["uuid"]}]
            }
            system_results[sys_name]["findings"].append(finding)
        else:
            observation["title"] = f"PASS: {row.controlName}"
            observation["props"] = [{"name": "status", "value": "satisfied"}]

        system_results[sys_name]["observations"].append(observation)

    # Add Results to Final JSON
    for sys_name, res_obj in system_results.items():
        oscal_data["assessment-results"]["results"].append(res_obj)

    return oscal_data


@router.get("/oscal")
async def export_oscal(
    system: Optional[str] = Query(None, description="Filter by system name"),
    framework: Optional[str] = Query(None, description="Filter by framework/control"),
    download: bool = Query(False, description="Force download as file"),
    current_user: User = Depends(require_permission("compliance.read")),
):
    """
    Export compliance data as NIST OSCAL Assessment Results (JSON).
    
    This format is compatible with:
    - FedRAMP automation tools
    - eMASS import
    - ComplyTime integration
    - GRC platforms supporting OSCAL
    
    Returns a valid OSCAL 1.1.2 Assessment Results document.
    """
    oscal_data = generate_oscal_from_store(
        system_filter=system,
        framework_filter=framework,
    )
    
    if download:
        filename = f"pact-oscal-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        return Response(
            content=json.dumps(oscal_data, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    
    return oscal_data


@router.get("/oscal/poam")
async def export_poam(
    current_user: User = Depends(require_permission("compliance.read")),
):
    """
    Export Plan of Action and Milestones (POA&M) for failed controls.
    
    Lists all current failures with recommended remediation timeline.
    """
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT DISTINCT ?systemName ?controlName ?time ?evidenceLink
    WHERE {
        GRAPH ?g {
            ?assess pact:hasVerdict "FAIL" ;
                    pact:validatesControl ?control ;
                    pact:evaluatedEvidence ?ev ;
                    pact:generatedAt ?time .
            
            ?ev pact:evidenceSourceUrl ?evidenceLink .
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName .
            
            ?control rdfs:label ?controlName .
        }
    }
    ORDER BY ?controlName DESC(?time)
    """
    
    try:
        results = db.query(query)
    except Exception:
        results = []
    
    poam_items = []
    for row in results:
        poam_items.append({
            "uuid": str(uuid.uuid4()),
            "title": f"Remediate {row.controlName} on {row.systemName}",
            "description": f"Control validation failed. Evidence: {row.evidenceLink}",
            "status": "open",
            "priority": "high",
            "system": str(row.systemName) if row.systemName else "Unknown",
            "control": str(row.controlName) if row.controlName else "Unknown",
            "detected_at": str(row.time) if row.time else None,
            "due_date": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat(),
        })
    
    return {
        "poam": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "PACT Plan of Action and Milestones",
                "last-modified": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            },
            "items": poam_items,
            "total_open": len(poam_items),
        }
    }

