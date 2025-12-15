import json
import datetime
from rdflib import Graph, Literal, BNode, RDF, Namespace, URIRef
from rdflib.namespace import XSD, RDFS
from pyshacl import validate

# 1. Setup Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
UCO_CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")
SH = Namespace("http://www.w3.org/ns/shacl#")

# 2. Ingest Data (List of Events)
try:
    with open('raw_event.json', 'r') as f:
        event_stream = json.load(f)
except FileNotFoundError:
    print("Error: raw_event.json not found.")
    exit()

print(f"--- Step 1: Ingested {len(event_stream)} Events ---")

# 3. Create the Evidence Graph
data_graph = Graph()
data_graph.bind("pact", PACT)
data_graph.bind("uco-obs", UCO_OBS)

# We need to keep track of the nodes we create so we can link them later
evidence_tracker = [] 

for event in event_stream:
    evidence_node = BNode() # Create a unique ID for this specific event
    
    # Store it in our list so we can create an assessment for it later
    evidence_tracker.append({
        "node": evidence_node,
        "description": f"{event['type']} event",
        "id": event.get("id", "unknown")
    })

    if event["type"] == "file_access":
        # Map File Data
        data_graph.add((evidence_node, RDF.type, UCO_OBS.File))
        data_graph.add((evidence_node, UCO_OBS.fileName, Literal(event["file"]["name"])))
        data_graph.add((evidence_node, UCO_OBS.owner, Literal(event["user"]["name"])))
        print(f"Mapped File: {event['file']['name']}")
        
    elif event["type"] == "network_connection":
        # Map Network Data
        data_graph.add((evidence_node, RDF.type, UCO_OBS.NetworkConnection))
        data_graph.add((evidence_node, UCO_OBS.destinationPort, Literal(event["destination"]["port"], datatype=XSD.integer)))
        data_graph.add((evidence_node, UCO_OBS.protocol, Literal(event["protocol"])))
        print(f"Mapped Network: Port {event['destination']['port']}")

# 4. Load Policy
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
# Now we loop through the items we tracked and create a record for EACH one.
print("--- Step 3: Generating PACT Compliance Records ---")

timestamp = datetime.datetime.now().isoformat()

for item in evidence_tracker:
    assessment_node = BNode()
    
    # 1. Define the Assessment Object
    data_graph.add((assessment_node, RDF.type, PACT.ComplianceAssessment))
    data_graph.add((assessment_node, RDFS.label, Literal(f"Check for {item['id']}")))
    data_graph.add((assessment_node, UCO_CORE.objectCreatedTime, Literal(timestamp, datatype=XSD.dateTime)))
    
    # 2. Link to Evidence
    data_graph.add((assessment_node, PACT.evaluatedEvidence, item['node']))
    
    # 3. Determine Verdict (Did this specific node fail?)
    # We query the SHACL results graph to see if this node is listed as a "focusNode" for a violation.
    # If the node is found in the failure report, it FAILED. Otherwise, it PASSED.
    is_failure = (None, SH.focusNode, item['node']) in results_graph
    
    verdict = "FAIL" if is_failure else "PASS"
    data_graph.add((assessment_node, PACT.hasVerdict, Literal(verdict)))
    
    print(f" > Assessment for {item['description']}: {verdict}")

# 7. Print the Final Graph
print("\n=== FINAL PACT GRAPH (Multi-Domain) ===")
print(data_graph.serialize(format='turtle'))

# Save the graph to a file so we can visualize it
data_graph.serialize(destination='pact_graph.ttl', format='turtle')
print("✅ Graph saved to 'pact_graph.ttl'")