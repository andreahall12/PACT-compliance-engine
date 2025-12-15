from rdflib import Graph, Literal, BNode, RDF, Namespace, URIRef
from rdflib.namespace import XSD, RDFS
from pyshacl import validate
import datetime

# 1. Setup Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
UCO_CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")

import json  # Add this at the very top with your other imports

# ... (keep your namespaces setup)

# 2. Ingest Data (REAL INPUT)
# Instead of fake data, we load the OCSF log file
with open('raw_event.json', 'r') as f:
    ocsf_log = json.load(f)

# Map OCSF log to our simple internal format
# (In a real app, this part is called "Normalization")
raw_log = {
    "filename": ocsf_log['file']['name'],
    "owner": ocsf_log['user']['name'],
    "path": ocsf_log['file']['path']
}

print(f"--- Step 1: Ingested Log for {raw_log['filename']} ---")
# 3. Create the Graph (The "Evidence Store")
data_graph = Graph()
data_graph.bind("pact", PACT)
data_graph.bind("uco-obs", UCO_OBS)

file_node = BNode() # This represents the specific file we found

data_graph.add((file_node, RDF.type, UCO_OBS.File))
data_graph.add((file_node, UCO_OBS.owner, Literal(raw_log["owner"])))
data_graph.add((file_node, UCO_OBS.fileName, Literal(raw_log["filename"])))

# 4. Load Policy (The Rules)
shacl_graph = Graph()
shacl_graph.parse("policy_rules.ttl", format="turtle")

# 5. Run the Assessment
print("--- Step 2: Validating Logic ---")
conforms, results_graph, results_text = validate(
    data_graph,
    shacl_graph=shacl_graph,
    ont_graph=None,
    inference='rdfs',
    debug=False
)

# 6. GENERATE PACT TRACEABILITY ARTIFACT
# This is the "Magic Step". We create a permanent record of this check.
# 6. GENERATE PACT TRACEABILITY ARTIFACT
print("--- Step 3: Generating PACT Compliance Record ---")

assessment_node = BNode() 

# A. Define the Assessment
data_graph.add((assessment_node, RDF.type, PACT.ComplianceAssessment))
data_graph.add((assessment_node, RDFS.label, Literal("Automated Config Check")))

# B. Link to GOVERNANCE (The "Why")
# We assert that this check validates NIST 800-53 Control AC-6
nist_control = URIRef("https://nvd.nist.gov/800-53/AC-6")
data_graph.add((assessment_node, PACT.validatesControl, nist_control))

# C. Link to EVIDENCE (The "What")
data_graph.add((assessment_node, PACT.evaluatedEvidence, file_node))

# D. Link to RESULT (The "Verdict")
verdict = "PASS" if conforms else "FAIL"
data_graph.add((assessment_node, PACT.hasVerdict, Literal(verdict)))

# Add Timestamp
timestamp = datetime.datetime.now().isoformat()
data_graph.add((assessment_node, UCO_CORE.objectCreatedTime, Literal(timestamp, datatype=XSD.dateTime)))

# 7. Print the Final Graph
print("\n=== FINAL PACT GRAPH (The Bridge) ===")
print(data_graph.serialize(format='turtle'))