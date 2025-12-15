from rdflib import Graph, Namespace

# Load the generated graph
g = Graph()
g.parse("db/pact_history.trig", format="trig")

PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")

print("--- PACT Blast Radius Analysis ---\n")

# SPARQL Query: Find Business Processes impacted by Failed Controls
query = """
PREFIX pact: <http://your-org.com/ns/pact#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?processName ?systemName ?controlName ?verdict
WHERE {
    # 1. Find Assessments that FAILED
    ?assessment pact:hasVerdict "FAIL" ;
                pact:validatesControl ?control ;
                pact:evaluatedEvidence ?evidence .
    
    ?control rdfs:label ?controlName .

    # 2. Trace Evidence back to the System
    ?system pact:hasComponent ?evidence ;
            rdfs:label ?systemName ;
            pact:supports ?process .

    # 3. Trace System to Business Process
    ?process rdfs:label ?processName .
}
"""

results = g.query(query)

print(f"{'BUSINESS PROCESS':<35} | {'SYSTEM':<25} | {'FAILED CONTROL':<30}")
print("-" * 95)

for row in results:
    print(f"{str(row.processName):<35} | {str(row.systemName):<25} | {str(row.controlName):<30}")

print("\nAnalysis Complete.")

