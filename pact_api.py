from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import uvicorn
import json
import os

from pact_logic import run_assessment
from pact_store import db

# OpenAI Setup
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

app = FastAPI(title="PACT Compliance API", version="1.0.0")

# Enable CORS for the visualization frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_compliance_context():
    """
    Extracts relevant compliance state from the graph to feed the LLM.
    """
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>

    SELECT ?systemName ?processName ?controlName ?verdict ?assetName ?time (GROUP_CONCAT(?mappedReq; separator=", ") AS ?impactedFrameworks)
    WHERE {
        GRAPH ?g {
            ?assessment pact:hasVerdict ?verdict ;
                        pact:validatesControl ?control ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
            
            { ?ev uco-obs:fileName ?assetName } UNION { ?ev uco-obs:destinationPort ?assetName }
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName ;
                    pact:supports ?process .
                    
            ?process rdfs:label ?processName .
            ?control rdfs:label ?controlName .
        }
        OPTIONAL { ?control pact:satisfiesRequirement ?mappedReq . }
    }
    GROUP BY ?systemName ?processName ?controlName ?verdict ?assetName ?time
    ORDER BY DESC(?time)
    LIMIT 50
    """
    results = db.query(query)
    context_data = []

    for row in results:
        context_data.append({
            "timestamp": str(row.time),
            "system": str(row.systemName),
            "process": str(row.processName),
            "control": str(row.controlName),
            "status": str(row.verdict),
            "asset": str(row.assetName),
            "impacted_frameworks": str(row.impactedFrameworks) if row.impactedFrameworks else "None"
        })
    return context_data

@app.get("/")
def home():
    return {"message": "PACT Compliance Engine is Running. Access docs at /docs"}

@app.post("/ingest")
def ingest_events(events: List[Dict[str, Any]] = Body(...)):
    """
    Ingest a list of OCSF-like JSON events, run compliance checks, and store the result.
    """
    if not events:
        raise HTTPException(status_code=400, detail="No events provided")
    
    # Run the Logic
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

@app.post("/chat")
def chat_with_auditor(payload: Dict[str, str] = Body(...)):
    question = payload.get("question")
    if not question:
        raise HTTPException(status_code=400, detail="No question provided")

    api_key = os.getenv("OPENAI_API_KEY")
    context_data = get_compliance_context()
    context_str = json.dumps(context_data, indent=2)

    # NEW: Fetch Threat Context to answer "Does this mitigate X?"
    threat_sparql = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?vulnName ?controlName ?systemName ?verdict WHERE {
        ?control pact:mitigates ?vuln . ?vuln rdfs:label ?vulnName . ?control rdfs:label ?controlName .
        GRAPH ?g { ?assess pact:validatesControl ?control ; pact:hasVerdict ?verdict ; pact:evaluatedEvidence ?ev . ?system pact:hasComponent ?ev ; rdfs:label ?systemName . }
    } LIMIT 20
    """
    threat_results = db.query(threat_sparql)
    threat_data = []
    for row in threat_results:
        threat_data.append({
            "vulnerability": str(row.vulnName),
            "mitigated_by": str(row.controlName),
            "system": str(row.systemName),
            "status": str(row.verdict)
        })
    
    combined_context = {
        "compliance_failures": context_data,
        "threat_mitigations": threat_data
    }
    context_str = json.dumps(combined_context, indent=2)

    if not api_key:
         return {
             "answer": "⚠️ **No OPENAI_API_KEY found.**\n\nI cannot generate a real AI response, but here is the **Raw Context** I would have sent to the LLM based on the Graph:\n\n```json\n" + context_str + "\n```"
         }
    
    if not OpenAI:
        return {"answer": "Error: OpenAI library not installed."}

    client = OpenAI(api_key=api_key)

    system_prompt = f"""
    You are an expert Security Compliance Auditor named 'PACT AI'.
    You have access to a semantic knowledge graph of the organization's security posture.
    The current state of the graph (recent assessments and threat mitigations) is provided below in JSON format.

    CONTEXT DATA:
    {context_str}

    INSTRUCTIONS:
    - Answer the user's question based ONLY on the provided context.
    - If the user asks if a vulnerability is mitigated (e.g. Log4Shell), check the 'threat_mitigations' list.
    - If the verdict is 'PASS', say it IS mitigated. If 'FAIL', say it is EXPOSED.
    - If a system has failed a control, explain WHY (the asset involved) and the IMPACT (the business process).
    - Format your response in Markdown (use bolding for Systems and Controls).
    - Be concise and professional.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": question}
            ]
        )
        return {"answer": response.choices[0].message.content}
    except Exception as e:
        return {"answer": f"Error calling OpenAI: {str(e)}"}

@app.get("/compliance/blast-radius")
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
        # Find latest failures
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

@app.get("/compliance/drift")
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

@app.get("/compliance/threats")
def check_threat_mitigation(vulnerability: str = None):
    """
    Checks if specific vulnerabilities are mitigated by active controls.
    Usage: /compliance/threats?vulnerability=Log4Shell
    """
    if not vulnerability:
        # Default: Show all mapped threats
        sparql = """
        PREFIX pact: <http://your-org.com/ns/pact#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        
        SELECT ?vulnName ?controlName ?systemName ?verdict
        WHERE {
            # 1. Define Threat Landscape
            ?control pact:mitigates ?vuln .
            ?vuln rdfs:label ?vulnName .
            ?control rdfs:label ?controlName .
            
            # 2. Check Assessment Status (Most Recent)
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
        # Filter by specific vulnerability
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

@app.get("/compliance/stats")
def stats():
    return db.get_stats()

@app.get("/visualize", response_class=HTMLResponse)
def serve_viz():
    with open("pact_viz.html", "r") as f:
        return f.read()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
