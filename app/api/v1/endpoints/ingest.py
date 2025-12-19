from fastapi import APIRouter, HTTPException, Body
from typing import List, Dict, Any
from app.core.engine import run_assessment
from app.core.store import db

router = APIRouter()

@router.post("/")
def ingest_events(events: List[Dict[str, Any]] = Body(...)):
    """
    Ingest a list of OCSF-like JSON events, run compliance checks, and store the result.
    """
    if not events:
        raise HTTPException(status_code=400, detail="No events provided")
    
    try:
        scan_uri, graph_data = run_assessment(events)
        
        # Save to Store
        db.add_graph(scan_uri, graph_data)
        
        return {
            "status": "success", 
            "scan_id": scan_uri, 
            "triples_generated": len(graph_data)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

