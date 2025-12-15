import json
import datetime
import hashlib
from rdflib import Graph, Literal, BNode, RDF, Namespace, URIRef
from rdflib.namespace import XSD, RDFS
from pyshacl import validate

# Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
UCO_CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")
SH = Namespace("http://www.w3.org/ns/shacl#")

from app.core.config import SYSTEM_CONTEXT_FILE, POLICY_RULES_FILE

def run_assessment(event_stream, system_context_file=SYSTEM_CONTEXT_FILE, policy_file=POLICY_RULES_FILE):
    """
    Core Logic: Ingests Events -> Maps to RDF -> Validates -> Returns Result Graph
    """
    timestamp = datetime.datetime.now().isoformat()
    scan_uri = URIRef(f"http://your-org.com/ns/pact/graph/{timestamp}")
    
    # 1. Create Data Graph for this Scan
    data_graph = Graph(identifier=scan_uri)
    data_graph.bind("pact", PACT)
    data_graph.bind("uco-obs", UCO_OBS)
    
    # Load Context
    data_graph.parse(system_context_file, format="turtle")
    
    # Define Controls
    control_ac3 = PACT.Control_AC3
    data_graph.add((control_ac3, RDF.type, PACT.Control))
    data_graph.add((control_ac3, RDFS.label, Literal("NIST AC-3: Access Enforcement")))

    control_cm7 = PACT.Control_CM7
    data_graph.add((control_cm7, RDF.type, PACT.Control))
    data_graph.add((control_cm7, RDFS.label, Literal("NIST CM-7: Least Functionality")))

    evidence_tracker = [] 

    # 2. Map Events to RDF
    for event in event_stream:
        # Stable ID
        event_id = event.get("id")
        if not event_id:
            event_hash = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
            event_id = f"hash-{event_hash[:8]}"
            
        evidence_uri = PACT[f"evidence/{event_id}"]
        evidence_node = URIRef(evidence_uri)
        
        deep_link = f"https://splunk.your-org.com/en-US/app/search/search?q=search%20id%3D{event_id}"

        evidence_tracker.append({
            "node": evidence_node,
            "id": event_id,
            "type": event["type"]
        })

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

    # 3. Validate
    # Support loading external/Gemara rules if present
    shacl_graph = Graph()
    if "gemara" in policy_file:
        print(f"   [Logic] Loading Gemara-compiled rules from {policy_file}...")
    
    shacl_graph.parse(policy_file, format="turtle")
    
    conforms, results_graph, results_text = validate(
        data_graph,
        shacl_graph=shacl_graph,
        ont_graph=None,
        inference='rdfs',
        debug=False
    )

    # 4. Generate Assessment Records
    for item in evidence_tracker:
        assessment_node = BNode()
        data_graph.add((assessment_node, RDF.type, PACT.ComplianceAssessment))
        data_graph.add((assessment_node, RDFS.label, Literal(f"Check for {item['id']}")))
        data_graph.add((assessment_node, PACT.generatedAt, Literal(timestamp, datatype=XSD.dateTime)))
        data_graph.add((assessment_node, PACT.evaluatedEvidence, item['node']))
        
        if item['type'] == 'file_access':
            data_graph.add((assessment_node, PACT.validatesControl, control_ac3))
        elif item['type'] == 'network_connection':
            data_graph.add((assessment_node, PACT.validatesControl, control_cm7))

        is_failure = (None, SH.focusNode, item['node']) in results_graph
        verdict = "FAIL" if is_failure else "PASS"
        data_graph.add((assessment_node, PACT.hasVerdict, Literal(verdict)))

    return str(scan_uri), data_graph

