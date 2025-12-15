import datetime
from rdflib import Dataset, Namespace

PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")

print("--- PACT Temporal Drift Analysis ---\n")

ds = Dataset()
ds.parse("db/pact_history.trig", format="trig")

query = """
PREFIX pact: <http://your-org.com/ns/pact#>
PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT ?systemName ?controlName ?identifier ?time1 ?time2 ?deepLink
WHERE {
    # ----------------------------------------------------------
    # 1. FIND THE CURRENT FAILURE (State T2)
    # ----------------------------------------------------------
    GRAPH ?g2 {
        ?assess2 pact:hasVerdict "FAIL" ;
                 pact:validatesControl ?control ;
                 pact:evaluatedEvidence ?ev2 ;
                 pact:generatedAt ?time2 .
        
        ?ev2 uco-obs:fileName ?identifier ;
             pact:evidenceSourceUrl ?deepLink .
        
        ?system pact:hasComponent ?ev2 .
        ?system rdfs:label ?systemName .
        ?control rdfs:label ?controlName .
    }

    # ----------------------------------------------------------
    # 2. FIND THE PREVIOUS SUCCESS (State T1)
    # ----------------------------------------------------------
    GRAPH ?g1 {
        ?assess1 pact:hasVerdict "PASS" ;
                 pact:validatesControl ?control ;
                 pact:evaluatedEvidence ?ev1 ;
                 pact:generatedAt ?time1 .

        # Match on identifier (filename)
        ?ev1 uco-obs:fileName ?identifier .
    }

    FILTER (?time2 > ?time1)
}
ORDER BY DESC(?time2)
"""

try:
    results = ds.query(query)

    if len(results) == 0:
        print("No drift detected.")
    else:
        print(f"{'SYSTEM':<20} | {'DRIFTED CONTROL':<30} | {'ASSET':<20} | {'DEEP LINK (Technical Proof)':<50}")
        print("-" * 130)
        for row in results:
            ident = str(row.identifier)
            link = str(row.deepLink)
            print(f"{str(row.systemName):<20} | {str(row.controlName):<30} | {ident:<20} | {link:<50}")

except Exception as e:
    print(f"Query Error: {e}")

print("\nAnalysis Complete.")
