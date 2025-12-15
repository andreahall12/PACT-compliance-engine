import json
import datetime
import uuid
from rdflib import Dataset, Namespace

# Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
RDFS = Namespace("http://www.w3.org/2000/01/rdf-schema#")

def generate_oscal_report(graph_file='pact_history.trig', output_file='pact_oscal_results.json'):
    """
    Exports the PACT Knowledge Graph into a NIST OSCAL Assessment Results (JSON) format.
    This makes the data compatible with FedRAMP / eMASS / ComplyTime tools.
    """
    print(f"Loading Graph from {graph_file}...")
    ds = Dataset()
    try:
        ds.parse(graph_file, format='trig')
    except Exception as e:
        print(f"Error loading graph: {e}")
        return

    # 1. Initialize OSCAL Structure
    # This represents a "Security Assessment Report" (SAR)
    oscal_data = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "PACT Automated Compliance Assessment",
                "last-modified": datetime.datetime.now().isoformat(),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "roles": [
                    {"id": "auditor", "title": "Automated Auditor (PACT)"}
                ]
            },
            "import-ap": {
                "href": "https://raw.githubusercontent.com/complytime/baseline-demo/main/plan.json" # Mock Link to ComplyTime Plan
            },
            "results": []
        }
    }

    # 2. Query the Graph for Latest Status per Control/System
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT ?systemName ?controlName ?verdict ?time ?evidenceLink ?asset
    WHERE {
        GRAPH ?g {
            ?assess pact:hasVerdict ?verdict ;
                    pact:validatesControl ?control ;
                    pact:evaluatedEvidence ?ev ;
                    pact:generatedAt ?time .
            
            ?ev pact:evidenceSourceUrl ?evidenceLink .
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName .
            
            ?control rdfs:label ?controlName .
            
            # Get Asset Name for context
            OPTIONAL { ?ev <https://ontology.unifiedcyberontology.org/uco/observable/fileName> ?asset }
            OPTIONAL { ?ev <https://ontology.unifiedcyberontology.org/uco/observable/destinationPort> ?asset }
        }
    }
    ORDER BY DESC(?time)
    """
    
    results = ds.query(query)

    # Group by System for clearer reporting
    system_results = {}

    for row in results:
        sys_name = str(row.systemName)
        if sys_name not in system_results:
            system_results[sys_name] = {
                "uuid": str(uuid.uuid4()),
                "title": f"Assessment of {sys_name}",
                "description": "Automated continuous monitoring scan.",
                "start": datetime.datetime.now().isoformat(),
                "observations": []
            }
            
        # Create an OSCAL "Observation" for each finding
        observation = {
            "uuid": str(uuid.uuid4()),
            "description": f"Check for {row.controlName} on {row.asset if row.asset else 'Unknown Asset'}",
            "methods": ["TEST-AUTOMATED"],
            "types": ["finding"],
            "relevant-evidence": [
                {
                    "href": str(row.evidenceLink),
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
        
        # Add Finding status (Satisfied/Not Satisfied)
        # Note: OSCAL uses "findings" to represent negative results primarily, 
        # but observations track the raw check.
        if str(row.verdict) == "FAIL":
            observation["title"] = f"FAILURE: {row.controlName}"
            observation["props"] = [{"name": "status", "value": "fail"}]
        else:
            observation["title"] = f"PASS: {row.controlName}"
            observation["props"] = [{"name": "status", "value": "pass"}]
            
        system_results[sys_name]["observations"].append(observation)

    # 3. Add Results to Final JSON
    for sys_name, res_obj in system_results.items():
        oscal_data["assessment-results"]["results"].append(res_obj)

    # 4. Save to File
    with open(output_file, 'w') as f:
        json.dump(oscal_data, f, indent=2)
        
    print(f"✅ Generated OSCAL Assessment Results: {output_file}")
    return oscal_data

if __name__ == "__main__":
    generate_oscal_report()

