from fastapi import APIRouter
from app.core.store import db

router = APIRouter()

@router.get("/blast-radius")
def get_blast_radius():
    """
    Returns high-impact failures linking Controls -> Evidence -> Systems -> Business Processes.
    """
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>

    SELECT ?systemName ?controlName ?identifier ?processName ?deepLink ?verdict ?time (GROUP_CONCAT(?mappedReq; separator=", ") AS ?impactedFrameworks)
    WHERE {
        GRAPH ?g {
            ?assessment pact:hasVerdict "FAIL" ;
                        pact:validatesControl ?control ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
            
            ?ev pact:evidenceSourceUrl ?deepLink .
            { ?ev uco-obs:fileName ?identifier } UNION { ?ev uco-obs:destinationPort ?identifier }
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName ;
                    pact:supports ?process .
                    
            ?process rdfs:label ?processName .
            ?control rdfs:label ?controlName .
        }
        OPTIONAL { ?control pact:satisfiesRequirement ?mappedReq . }
    }
    GROUP BY ?systemName ?controlName ?identifier ?processName ?deepLink ?verdict ?time
    ORDER BY DESC(?time)
    LIMIT 50
    """
    results = db.query(query)
    
    output = []
    for row in results:
        output.append({
            "process": str(row.processName),
            "system": str(row.systemName),
            "control": str(row.controlName),
            "asset": str(row.identifier),
            "timestamp": str(row.time),
            "link": str(row.deepLink),
            "impacted_frameworks": str(row.impactedFrameworks) if row.impactedFrameworks else "None"
        })
        
    return output

@router.get("/drift")
def get_drift():
    """
    Identifies assets that have drifted from PASS to FAIL status.
    """
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

    SELECT ?systemName ?controlName ?identifier ?time1 ?time2 ?deepLink
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
    results = db.query(query)
    
    output = []
    for row in results:
        output.append({
            "system": str(row.systemName),
            "control": str(row.controlName),
            "asset": str(row.identifier),
            "previous_pass": str(row.time1),
            "current_fail": str(row.time2),
            "link": str(row.deepLink)
        })
    return output

@router.get("/threats")
def check_threat_mitigation(vulnerability: str = None):
    """
    Checks if specific vulnerabilities are mitigated by active controls.
    """
    if not vulnerability:
        sparql = """
        PREFIX pact: <http://your-org.com/ns/pact#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        
        SELECT ?vulnName ?controlName ?systemName ?verdict
        WHERE {
            ?control pact:mitigates ?vuln .
            ?vuln rdfs:label ?vulnName .
            ?control rdfs:label ?controlName .
            
            GRAPH ?g {
                ?assess pact:validatesControl ?control ;
                        pact:hasVerdict ?verdict ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
                        
                ?system pact:hasComponent ?ev ;
                        rdfs:label ?systemName .
            }
        }
        ORDER BY DESC(?time)
        LIMIT 50
        """
    else:
        sparql = f"""
        PREFIX pact: <http://your-org.com/ns/pact#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        
        SELECT ?vulnName ?controlName ?systemName ?verdict
        WHERE {{
            ?control pact:mitigates ?vuln .
            ?vuln rdfs:label ?vulnName .
            FILTER (REGEX(?vulnName, "{vulnerability}", "i"))
            
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
        
    results = db.query(sparql)
    output = []
    for row in results:
        output.append({
            "vulnerability": str(row.vulnName),
            "mitigating_control": str(row.controlName),
            "system": str(row.systemName),
            "status": str(row.verdict)
        })
    return output

@router.get("/stats")
def stats():
    return db.get_stats()



