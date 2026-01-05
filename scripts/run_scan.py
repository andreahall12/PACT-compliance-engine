import json
import datetime
import argparse
import os
import hashlib
from urllib.parse import quote_plus
from rdflib import Graph, Literal, BNode, RDF, Namespace, Dataset, URIRef
from rdflib.namespace import XSD, RDFS
from pyshacl import validate

# CLI Setup
parser = argparse.ArgumentParser(description='PACT Engine - Temporal Compliance')
parser.add_argument('--input', type=str, required=True, help='Input event JSON file')
parser.add_argument('--timestamp', type=str, default=None, help='ISO Timestamp for this scan')
args = parser.parse_args()

# 1. Setup Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
UCO_CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")
SH = Namespace("http://www.w3.org/ns/shacl#")

# Timestamp management
scan_time = args.timestamp if args.timestamp else datetime.datetime.now().isoformat()
# Create a unique Named Graph URI for this specific point-in-time scan
scan_uri = URIRef(f"http://your-org.com/ns/pact/graph/{scan_time}")

# 2. Ingest Data
try:
    with open(args.input, 'r') as f:
        event_stream = json.load(f)
except FileNotFoundError:
    print(f"Error: {args.input} not found.")
    exit()

print(f"--- Processing Scan: {scan_time} ---")

# 3. Create the Dataset (Supports Named Graphs)
ds = Dataset()
# We work on a specific named graph context
data_graph = ds.graph(scan_uri)

data_graph.bind("pact", PACT)
data_graph.bind("uco-obs", UCO_OBS)
data_graph.bind("uco-core", UCO_CORE)

# LOAD CONTEXT: System definitions
data_graph.parse("data/context/system_context.ttl", format="turtle")

# Define Controls (Governance Layer)
control_ac3 = PACT.Control_AC3
data_graph.add((control_ac3, RDF.type, PACT.Control))
data_graph.add((control_ac3, RDFS.label, Literal("NIST AC-3: Access Enforcement")))

control_cm7 = PACT.Control_CM7
data_graph.add((control_cm7, RDF.type, PACT.Control))
data_graph.add((control_cm7, RDFS.label, Literal("NIST CM-7: Least Functionality")))

evidence_tracker = [] 

for event in event_stream:
    # --- STABLE URI GENERATION ---
    # Create a deterministic ID based on the event ID (or content if ID missing)
    event_id = event.get("id")
    if not event_id:
        # Fallback to hash of content
        event_hash = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
        event_id = f"hash-{event_hash[:8]}"
        
    # Evidence is now a First-Class Citizen with a URL
    evidence_uri = PACT[f"evidence/{event_id}"]
    evidence_node = URIRef(evidence_uri)
    
    # --- DEEP LINK GENERATION ---
    # Simulating a link to a log aggregation system (e.g. Splunk)
    # In reality, this would be constructed from your SIEM's deep-link format
    deep_link = (
        "https://splunk.your-org.com/en-US/app/search/search?q="
        + quote_plus(f"search id={event_id}")
    )

    evidence_tracker.append({
        "node": evidence_node,
        "description": f"{event['type']} event",
        "id": event_id,
        "type": event["type"]
    })

    # Add Deep Link
    data_graph.add((evidence_node, PACT.evidenceSourceUrl, Literal(deep_link, datatype=XSD.anyURI)))

    if event["type"] == "file_access":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.File))
        data_graph.add((evidence_node, UCO_OBS.fileName, Literal(event["file"]["name"])))
        data_graph.add((evidence_node, UCO_OBS.owner, Literal(event["user"]["name"])))
        data_graph.add((PACT.HRPortal, PACT.hasComponent, evidence_node))
        
    elif event["type"] == "network_connection":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.NetworkConnection))
        data_graph.add((evidence_node, UCO_OBS.destinationPort, Literal(event["destination"]["port"], datatype=XSD.integer)))
        data_graph.add((evidence_node, UCO_OBS.protocol, Literal(event["protocol"])))
        data_graph.add((PACT.PaymentGatewayCluster, PACT.hasComponent, evidence_node))

# 4. Load Policy
shacl_graph = Graph()
shacl_graph.parse("data/policies/policy_rules.ttl", format="turtle")

# 5. Run Assessment
conforms, results_graph, results_text = validate(
    data_graph,
    shacl_graph=shacl_graph,
    ont_graph=None,
    inference='rdfs',
    debug=False
)

# 6. Generate Records in the Named Graph
for item in evidence_tracker:
    # Assessments are unique PER SCAN, so they stay as BNodes or Timestamped URIs
    assessment_node = BNode()
    
    data_graph.add((assessment_node, RDF.type, PACT.ComplianceAssessment))
    data_graph.add((assessment_node, RDFS.label, Literal(f"Check for {item['id']}")))
    data_graph.add((assessment_node, PACT.generatedAt, Literal(scan_time, datatype=XSD.dateTime)))
    data_graph.add((assessment_node, PACT.evaluatedEvidence, item['node']))
    
    if item['type'] == 'file_access':
        data_graph.add((assessment_node, PACT.validatesControl, control_ac3))
    elif item['type'] == 'network_connection':
        data_graph.add((assessment_node, PACT.validatesControl, control_cm7))

    is_failure = (None, SH.focusNode, item['node']) in results_graph
    verdict = "FAIL" if is_failure else "PASS"
    data_graph.add((assessment_node, PACT.hasVerdict, Literal(verdict)))
    
    # print(f" > {item['id']}: {verdict}")

# 7. Append to History (TriG format)
history_file = 'db/pact_history.trig'
existing_ds = Dataset()

if os.path.exists(history_file):
    existing_ds.parse(history_file, format='trig')

# Merge current run into history
for s, p, o in data_graph:
    existing_ds.add((s, p, o, scan_uri))

existing_ds.serialize(destination=history_file, format='trig')
print(f"✅ Compliance State saved to '{history_file}' (Graph: {scan_uri})")
