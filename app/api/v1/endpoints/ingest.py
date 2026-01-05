from fastapi import APIRouter, HTTPException, Body
from typing import List, Dict, Any
from app.core.engine import run_assessment
from app.core.store import db

router = APIRouter()

from pydantic import BaseModel, Field

class IngestRequest(BaseModel):
    events: List[Dict[str, Any]]
    target_systems: List[str] = Field(default_factory=list)
    target_frameworks: List[str] = Field(default_factory=list)

@router.post("")
def ingest_events(request: IngestRequest = Body(...)):
    """
    Ingest a list of OCSF-like JSON events, run compliance checks, and store the result.
    """
    if not request.events:
        raise HTTPException(status_code=400, detail="No events provided")
    
    try:
        scan_uri, graph_data = run_assessment(
            request.events, 
            target_systems=request.target_systems,
            target_frameworks=request.target_frameworks
        )
        
        # Save to Store
        db.add_graph(scan_uri, graph_data)
        
        return {
            "status": "success", 
            "scan_id": scan_uri, 
            "triples_generated": len(graph_data)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

