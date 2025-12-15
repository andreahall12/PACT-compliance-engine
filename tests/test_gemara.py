import argparse
import json
import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.engine import run_assessment
from app.core.store import db
from rdflib import Namespace

PACT = Namespace("http://your-org.com/ns/pact#")

def test_gemara_integration():
    print("--- Testing Gemara Integration ---")
    
    # 1. Define a test event (Root File Access)
    # This VIOLATES the Gemara_AC3_Shape (No Root Owner)
    events = [
        {
            "id": "gemara-test-001",
            "type": "file_access",
            "file": {
                "name": "gemara_test_config.yaml",
                "path": "/etc/gemara"
            },
            "user": { "name": "root" }
        }
    ]
    
    # 2. Run Assessment using GEMARA Rules
    print("Running PACT Engine with Gemara Rules...")
    # Use the new path for the test rule file
    scan_uri, graph_data = run_assessment(events, policy_file="data/policies/gemara_generated_rules.ttl")
    
    # 3. Save to Store
    db.add_graph(scan_uri, graph_data)
    
    print(f"\n✅ Scan Complete: {scan_uri}")
    print("Verifying if the Assessment Verdict is FAIL...")
    
    # 4. Verify Result
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    SELECT ?verdict WHERE {
        ?assess pact:hasVerdict ?verdict .
    }
    """
    results = graph_data.query(query)
    
    verdict = None
    for row in results:
        verdict = str(row.verdict)
        print(f" > Found Verdict: {verdict}")
            
    if verdict == "FAIL":
        print("\n🎉 SUCCESS: PACT successfully enforced Gemara-compiled policies!")
    else:
        print("\n❌ FAILURE: Gemara rules were not enforced (Verdict was PASS).")

if __name__ == "__main__":
    test_gemara_integration()
