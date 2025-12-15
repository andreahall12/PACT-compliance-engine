from rdflib import Graph, Namespace
import pact_engine # Load the live graph from your engine

print("\n\n---------------------------------------------------")
print("   ACTING AS: INDEPENDENT AUDITOR SYSTEM")
print("---------------------------------------------------")

# 1. The Smart Query
# We use the OPTIONAL clause to handle different types of evidence
query_string = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    
    SELECT ?label ?verdict ?detail
    WHERE {
        ?assessment pact:hasVerdict ?verdict .
        ?assessment rdfs:label ?label .
        ?assessment pact:evaluatedEvidence ?evidence .
        
        # Filter: We only want FAILURES
        FILTER (?verdict = "FAIL")

        # LOGIC: Extract details depending on what the evidence IS
        OPTIONAL { 
            ?evidence uco-obs:fileName ?fname . 
            ?evidence uco-obs:owner ?owner .
            BIND(CONCAT("File: ", ?fname, " (Owner: ", ?owner, ")") AS ?detail)
        }
        OPTIONAL { 
            ?evidence uco-obs:destinationPort ?port .
            BIND(CONCAT("Network: Port ", STR(?port), " Open") AS ?detail)
        }
    }
"""

# 2. Ask the Question
g = pact_engine.data_graph
results = g.query(query_string)

# 3. Print the Unified Report
if len(results) == 0:
    print("✅ AUDIT PASSED: All systems compliant.")
else:
    print("❌ AUDIT FAILED: Non-compliance detected.\n")
    print(f"{'ASSESSMENT':<30} | {'DETAILS':<40}")
    print("-" * 75)
    
    for row in results:
        label = str(row.label)
        detail = str(row.detail) if row.detail else "Unknown Evidence Type"
        print(f"{label:<30} | {detail:<40}")