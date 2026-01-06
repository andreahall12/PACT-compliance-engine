import re

from fastapi import APIRouter, HTTPException
from app.core.store import db

router = APIRouter()

# =============================================================================
# Constants
# =============================================================================

SPARQL_PREFIXES = """
PREFIX pact: <http://your-org.com/ns/pact#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

DEFAULT_BLAST_LIMIT = 50
DEFAULT_THREATS_LIMIT = 50

_VULN_FILTER_RE = re.compile(r"^[A-Za-z0-9 _\\-\\.:/]{1,64}$")


# =============================================================================
# Helper Functions
# =============================================================================

def _run_query(query: str):
    """Execute a SPARQL query with standard prefixes."""
    return db.query(SPARQL_PREFIXES + query)


def _rows_to_list(results, mapper):
    """Convert SPARQL results to a list of dicts using a mapper function."""
    return [mapper(row) for row in results]

@router.get("/blast-radius")
def get_blast_radius():
    """
    Returns high-impact failures linking Controls -> Evidence -> Systems -> Business Processes.
    """
    query = f"""
    SELECT ?systemName ?controlName ?identifier ?processName ?deepLink ?verdict ?time (GROUP_CONCAT(?mappedReq; separator=", ") AS ?impactedFrameworks)
    WHERE {{
        GRAPH ?g {{
            ?assessment pact:hasVerdict "FAIL" ;
                        pact:validatesControl ?control ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
            
            ?ev pact:evidenceSourceUrl ?deepLink .
            {{ ?ev uco-obs:fileName ?identifier }} UNION {{ ?ev uco-obs:destinationPort ?identifier }}
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName ;
                    pact:supports ?process .
                    
            ?process rdfs:label ?processName .
            ?control rdfs:label ?controlName .
        }}
        OPTIONAL {{ ?control pact:satisfiesRequirement ?mappedReq . }}
    }}
    GROUP BY ?systemName ?controlName ?identifier ?processName ?deepLink ?verdict ?time
    ORDER BY DESC(?time)
    LIMIT {DEFAULT_BLAST_LIMIT}
    """
    
    def mapper(row):
        return {
            "process": str(row.processName),
            "system": str(row.systemName),
            "control": str(row.controlName),
            "asset": str(row.identifier),
            "timestamp": str(row.time),
            "link": str(row.deepLink),
            "impacted_frameworks": str(row.impactedFrameworks) if row.impactedFrameworks else "None"
        }
    
    return _rows_to_list(_run_query(query), mapper)

@router.get("/drift")
def get_drift():
    """
    Identifies assets that have drifted from PASS to FAIL status.
    
    Returns enhanced details including:
    - Actor/user who caused the drift
    - SHACL violation message explaining why
    - Event type and file path
    """
    query = """
    SELECT ?systemName ?controlName ?identifier ?time1 ?time2 ?deepLink 
           ?actorName ?ownerName ?changedBy ?eventType ?filePath ?violationMsg
    WHERE {
        GRAPH ?g2 {
            ?assess2 pact:hasVerdict "FAIL" ;
                     pact:validatesControl ?control ;
                     pact:evaluatedEvidence ?ev2 ;
                     pact:generatedAt ?time2 .
            ?ev2 uco-obs:fileName ?identifier ;
                 pact:evidenceSourceUrl ?deepLink .
            ?system pact:hasComponent ?ev2 ;
                    rdfs:label ?systemName .
            ?control rdfs:label ?controlName .
            
            # Optional: Actor name (explicit)
            OPTIONAL { ?ev2 pact:actorName ?actorName . }
            # Optional: Owner (file_access legacy)
            OPTIONAL { ?ev2 uco-obs:owner ?ownerName . }
            # Optional: Changed by (config_change legacy)
            OPTIONAL { ?ev2 pact:changedBy ?changedBy . }
            # Optional: Event type
            OPTIONAL { ?ev2 pact:eventType ?eventType . }
            # Optional: File path
            OPTIONAL { ?ev2 uco-obs:filePath ?filePath . }
            # Optional: SHACL violation message
            OPTIONAL { ?ev2 pact:violationMessage ?violationMsg . }
        }
        GRAPH ?g1 {
            ?assess1 pact:hasVerdict "PASS" ;
                     pact:validatesControl ?control ;
                     pact:evaluatedEvidence ?ev1 ;
                     pact:generatedAt ?time1 .
            ?ev1 uco-obs:fileName ?identifier .
        }
        FILTER (?time2 > ?time1)
    }
    ORDER BY DESC(?time2)
    """
    
    def mapper(row):
        # Determine actor: explicit actor > owner > changedBy > "Unknown"
        actor = None
        if hasattr(row, 'actorName') and row.actorName:
            actor = str(row.actorName)
        elif hasattr(row, 'ownerName') and row.ownerName:
            actor = str(row.ownerName)
        elif hasattr(row, 'changedBy') and row.changedBy:
            actor = str(row.changedBy)
        
        # Get violation message (the "why")
        why = None
        if hasattr(row, 'violationMsg') and row.violationMsg:
            why = str(row.violationMsg)
        
        return {
            "system": str(row.systemName),
            "control": str(row.controlName),
            "asset": str(row.identifier),
            "asset_path": str(row.filePath) if hasattr(row, 'filePath') and row.filePath else None,
            "event_type": str(row.eventType) if hasattr(row, 'eventType') and row.eventType else None,
            "actor": actor,
            "previous_pass": str(row.time1),
            "current_fail": str(row.time2),
            "link": str(row.deepLink),
            "why": why
        }
    
    return _rows_to_list(_run_query(query), mapper)

@router.get("/threats")
def check_threat_mitigation(vulnerability: str = None):
    """
    Checks if specific vulnerabilities are mitigated by active controls.
    """
    if not vulnerability:
        query = f"""
        SELECT ?vulnName ?controlName ?systemName ?verdict
        WHERE {{
            ?control pact:mitigates ?vuln .
            ?vuln rdfs:label ?vulnName .
            ?control rdfs:label ?controlName .
            
            GRAPH ?g {{
                ?assess pact:validatesControl ?control ;
                        pact:hasVerdict ?verdict ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
                        
                ?system pact:hasComponent ?ev ;
                        rdfs:label ?systemName .
            }}
        }}
        ORDER BY DESC(?time)
        LIMIT {DEFAULT_THREATS_LIMIT}
        """
    else:
        if not _VULN_FILTER_RE.fullmatch(vulnerability):
            raise HTTPException(
                status_code=400,
                detail="Invalid vulnerability filter. Use letters/numbers/space and -_.:/ (max 64 chars).",
            )

        # Escape for embedding in a SPARQL string literal.
        safe_vuln = vulnerability.replace("\\", "\\\\").replace('"', '\\"')
        query = f"""
        SELECT ?vulnName ?controlName ?systemName ?verdict
        WHERE {{
            ?control pact:mitigates ?vuln .
            ?vuln rdfs:label ?vulnName .
            FILTER (REGEX(?vulnName, "{safe_vuln}", "i"))
            
            ?control rdfs:label ?controlName .
            
            GRAPH ?g {{
                ?assess pact:validatesControl ?control ;
                        pact:hasVerdict ?verdict ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
                        
                ?system pact:hasComponent ?ev ;
                        rdfs:label ?systemName .
            }}
        }}
        ORDER BY DESC(?time)
        """
    
    def mapper(row):
        return {
            "vulnerability": str(row.vulnName),
            "mitigating_control": str(row.controlName),
            "system": str(row.systemName),
            "status": str(row.verdict)
        }
    
    return _rows_to_list(_run_query(query), mapper)

@router.get("/stats")
def stats():
    return db.get_stats()



