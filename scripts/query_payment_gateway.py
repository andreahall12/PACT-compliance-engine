import argparse
import sys
import os
# Add the project root to sys.path to import app.core.store
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.store import db

def query_system_failures(system_name):
    print(f"--- Querying Failures for: {system_name} ---")
    
    query = f"""
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT ?controlName ?verdict ?evidence ?time
    WHERE {{
        GRAPH ?g {{
            ?assessment pact:hasVerdict "FAIL" ;
                        pact:validatesControl ?control ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?sysLabel .
            
            FILTER(REGEX(?sysLabel, "{system_name}", "i"))
            
            ?control rdfs:label ?controlName .
            ?ev <https://ontology.unifiedcyberontology.org/uco/observable/destinationPort> ?evidence .
        }}
    }}
    ORDER BY DESC(?time)
    """
    
    results = db.query(query)
    
    if len(results) == 0:
        print("No failures found (or system name mismatch).")
    else:
        print(f"{'CONTROL':<40} | {'EVIDENCE':<10} | {'TIME'}")
        print("-" * 80)
        for row in results:
            print(f"{str(row.controlName):<40} | {str(row.evidence):<10} | {str(row.time)}")

if __name__ == "__main__":
    query_system_failures("Payment Gateway Prod")

