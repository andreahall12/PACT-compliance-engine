from rdflib import Graph, Namespace
from rdflib.plugins.sparql import prepareQuery

# 1. Load the PACT Graph (The Artifact we created)
# In a real system, we would load the 'turtle' output from the previous step.
# Here, we will just re-run the engine logic briefly to get the graph in memory, 
# or we can load a saved .ttl file. 
# For this demo, let's just use the engine to get the data live.

import pact_engine # We import your engine to get the graph!

print("\n\n---------------------------------------------------")
print("   ACTING AS: INDEPENDENT AUDITOR SYSTEM")
print("---------------------------------------------------")

# 2. Define the Question (SPARQL Query)
# We ask: "Find every Assessment that has a Verdict of FAIL, 
# and tell me which Control and which File caused it."
query_string = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
    
    SELECT ?control ?verdict ?filename ?owner
    WHERE {
        ?assessment pact:hasVerdict ?verdict .
        ?assessment pact:validatesControl ?control .
        ?assessment pact:evaluatedEvidence ?evidence .
        
        # Get details about the evidence
        ?evidence uco-obs:fileName ?filename .
        ?evidence uco-obs:owner ?owner .
        
        # Filter: We only care about FAILURES
        FILTER (?verdict = "FAIL")
    }
"""

# 3. Ask the Question
g = pact_engine.data_graph # This grabs the graph from your running engine
results = g.query(query_string)

# 4. Print the Management Report
if len(results) == 0:
    print("✅ AUDIT PASSED: No non-compliant controls found.")
else:
    print("❌ AUDIT FAILED: Non-compliance detected.\n")
    print(f"{'CONTROL':<35} | {'FILE':<25} | {'OWNER':<10}")
    print("-" * 75)
    
    for row in results:
        # Clean up the output to look nice
        control = str(row.control).replace("https://nvd.nist.gov/800-53/", "")
        filename = str(row.filename)
        owner = str(row.owner)
        print(f"{control:<35} | {filename:<25} | {owner:<10}")