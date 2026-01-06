"""
PACT Compliance Engine.

Core logic for:
- Mapping events to RDF (UCO ontology)
- SHACL validation against policies
- Generating compliance assessments
"""

import json
import datetime
import hashlib
import re
import uuid
from urllib.parse import quote_plus
from typing import List, Dict, Any, Optional, Tuple

from rdflib import Graph, Literal, BNode, RDF, Namespace, URIRef
from rdflib.namespace import XSD, RDFS
from pyshacl import validate

# Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
UCO_CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")
SH = Namespace("http://www.w3.org/ns/shacl#")

from app.core.config import SYSTEM_CONTEXT_FILE, POLICY_RULES_FILE, CONTROLS_FILE


# Event type to control mapping
# In production, this would be loaded from the ontology or a config
EVENT_CONTROL_MAP = {
    "file_access": "Control_AC3",       # Access Enforcement
    "network_connection": "Control_CM7", # Least Functionality
    "authentication": "Control_IA2",     # Identification and Authentication
    "api_call": "Control_AU12",          # Audit Generation
    "config_change": "Control_CM3",      # Configuration Change Control
}


def resolve_system_uri(
    data_graph: Graph,
    system_name: Optional[str],
    event_type: str,
) -> URIRef:
    """
    Resolve or create a system URI from the context graph.
    
    If the system exists in the context, return its URI.
    Otherwise, create a dynamic system node.
    """
    if not system_name:
        # Default system based on event type
        default_systems = {
            "file_access": "GenericFileServer",
            "network_connection": "GenericNetworkDevice",
            "authentication": "IdentityProvider",
            "api_call": "APIGateway",
            "config_change": "ConfigManagement",
        }
        system_name = default_systems.get(event_type, "UnknownSystem")
    
    # Try to find existing system by label
    safe_name = re.sub(r'[^A-Za-z0-9_-]', '_', system_name)
    system_uri = PACT[safe_name]
    
    # Check if system already exists in graph
    existing = list(data_graph.triples((system_uri, RDF.type, PACT.System)))
    
    if not existing:
        # Create the system node
        data_graph.add((system_uri, RDF.type, PACT.System))
        data_graph.add((system_uri, RDFS.label, Literal(system_name)))
    
    return system_uri


def resolve_control_uri(event_type: str) -> URIRef:
    """
    Map event type to the appropriate control.
    """
    control_id = EVENT_CONTROL_MAP.get(event_type, "Control_Unknown")
    return PACT[control_id]


def generate_safe_id(value: str) -> str:
    """
    Generate a URL-safe ID from an arbitrary string.
    """
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
        return value
    return f"hash-{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def map_event_to_rdf(
    data_graph: Graph,
    event: Dict[str, Any],
) -> Tuple[URIRef, str, URIRef]:
    """
    Map a single event to RDF triples.
    
    Returns:
        Tuple of (evidence_node, event_id, system_uri)
    """
    event_type = event.get("type", "unknown")
    event_id = event.get("id")
    
    # Generate stable ID if not provided
    if not event_id:
        event_hash = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
        event_id = f"auto-{event_hash[:8]}"
    
    safe_event_id = generate_safe_id(event_id)
    evidence_uri = PACT[f"evidence/{safe_event_id}"]
    evidence_node = URIRef(evidence_uri)
    
    # Generate deep link to source
    source_url = event.get("source_url")
    if not source_url:
        source_url = (
            "https://splunk.your-org.com/en-US/app/search/search?q="
            + quote_plus(f"search id={event_id}")
        )
    
    data_graph.add((evidence_node, PACT.evidenceSourceUrl, Literal(source_url, datatype=XSD.anyURI)))
    data_graph.add((evidence_node, PACT.eventId, Literal(event_id)))
    data_graph.add((evidence_node, PACT.eventType, Literal(event_type)))
    
    # Resolve system from event (dynamic, not hard-coded)
    system_name = event.get("system")
    system_uri = resolve_system_uri(data_graph, system_name, event_type)
    
    # Extract actor information (explicit actor field takes precedence)
    actor_info = event.get("actor", {})
    actor_name = actor_info.get("name") if actor_info else None
    
    # Map based on event type
    if event_type == "file_access":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.File))
        file_info = event.get("file", {})
        data_graph.add((evidence_node, UCO_OBS.fileName, Literal(file_info.get("name", "unknown"))))
        if file_info.get("path"):
            data_graph.add((evidence_node, UCO_OBS.filePath, Literal(file_info["path"])))
        user_info = event.get("user", {})
        owner_name = user_info.get("name", "unknown")
        data_graph.add((evidence_node, UCO_OBS.owner, Literal(owner_name)))
        # Store actor (use explicit actor, fallback to owner)
        effective_actor = actor_name or owner_name
        if effective_actor and effective_actor != "unknown":
            data_graph.add((evidence_node, PACT.actorName, Literal(effective_actor)))
        
    elif event_type == "network_connection":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.NetworkConnection))
        dest = event.get("destination", {})
        data_graph.add((evidence_node, UCO_OBS.destinationPort, Literal(dest.get("port", 0), datatype=XSD.integer)))
        if dest.get("ip"):
            data_graph.add((evidence_node, UCO_OBS.destinationAddress, Literal(dest["ip"])))
        data_graph.add((evidence_node, UCO_OBS.protocol, Literal(event.get("protocol", "tcp"))))
        # Store actor if provided
        if actor_name:
            data_graph.add((evidence_node, PACT.actorName, Literal(actor_name)))
        
    elif event_type == "authentication":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.Account))
        data_graph.add((evidence_node, PACT.authResult, Literal(event.get("result", "unknown"))))
        data_graph.add((evidence_node, PACT.authMethod, Literal(event.get("method", "unknown"))))
        user_info = event.get("user", {})
        login_name = user_info.get("name", "unknown")
        data_graph.add((evidence_node, UCO_OBS.accountLogin, Literal(login_name)))
        # Store actor (use explicit actor, fallback to login name)
        effective_actor = actor_name or login_name
        if effective_actor and effective_actor != "unknown":
            data_graph.add((evidence_node, PACT.actorName, Literal(effective_actor)))
        
    elif event_type == "api_call":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.URL))
        data_graph.add((evidence_node, PACT.apiEndpoint, Literal(event.get("endpoint", ""))))
        data_graph.add((evidence_node, PACT.apiMethod, Literal(event.get("method", "GET"))))
        data_graph.add((evidence_node, PACT.apiStatus, Literal(event.get("status_code", 0), datatype=XSD.integer)))
        # Store actor if provided
        if actor_name:
            data_graph.add((evidence_node, PACT.actorName, Literal(actor_name)))
        
    elif event_type == "config_change":
        data_graph.add((evidence_node, RDF.type, UCO_OBS.File))
        data_graph.add((evidence_node, PACT.configKey, Literal(event.get("key", ""))))
        data_graph.add((evidence_node, PACT.configOldValue, Literal(str(event.get("old_value", "")))))
        data_graph.add((evidence_node, PACT.configNewValue, Literal(str(event.get("new_value", "")))))
        user_info = event.get("user", {})
        changed_by = user_info.get("name", "unknown")
        data_graph.add((evidence_node, PACT.changedBy, Literal(changed_by)))
        # Store actor (use explicit actor, fallback to changedBy)
        effective_actor = actor_name or changed_by
        if effective_actor and effective_actor != "unknown":
            data_graph.add((evidence_node, PACT.actorName, Literal(effective_actor)))
        
    else:
        # Generic event type
        data_graph.add((evidence_node, RDF.type, PACT.GenericEvidence))
        # Store raw event data as JSON for reference
        data_graph.add((evidence_node, PACT.rawEventData, Literal(json.dumps(event))))
    
    # Link evidence to system
    data_graph.add((system_uri, PACT.hasComponent, evidence_node))
    
    return evidence_node, event_id, system_uri


def run_assessment(
    event_stream: List[Dict[str, Any]],
    system_context_file: str = str(SYSTEM_CONTEXT_FILE),
    policy_file: str = str(POLICY_RULES_FILE),
    target_systems: Optional[List[str]] = None,
    target_frameworks: Optional[List[str]] = None,
) -> Tuple[str, Graph]:
    """
    Core Logic: Ingests Events -> Maps to RDF -> Validates -> Returns Result Graph
    
    Args:
        event_stream: List of event dictionaries to process
        system_context_file: Path to system context TTL file
        policy_file: Path to SHACL policy rules file
        target_systems: Optional list of system names to filter
        target_frameworks: Optional list of framework/control names to filter
        
    Returns:
        Tuple of (scan_uri, data_graph)
    """
    # Generate unique scan ID using UUID + timestamp
    scan_uuid = uuid.uuid4()
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    scan_uri = URIRef(f"http://your-org.com/ns/pact/scan/{scan_uuid}")
    
    # Create Data Graph for this Scan
    data_graph = Graph(identifier=scan_uri)
    data_graph.bind("pact", PACT)
    data_graph.bind("uco-obs", UCO_OBS)
    data_graph.bind("uco-core", UCO_CORE)
    
    # Load Context (systems, processes) and Controls
    try:
        data_graph.parse(system_context_file, format="turtle")
    except Exception as e:
        print(f"Warning: Could not load system context: {e}")
        
    try:
        data_graph.parse(str(CONTROLS_FILE), format="turtle")
    except Exception as e:
        print(f"Warning: Could not load controls: {e}")

    evidence_tracker = []

    # Map Events to RDF
    for event in event_stream:
        # Filter by system if specified
        event_system = event.get("system")
        if target_systems and event_system and event_system not in target_systems:
            continue
        
        event_type = event.get("type", "unknown")
        
        # Map event to RDF
        evidence_node, event_id, system_uri = map_event_to_rdf(data_graph, event)
        
        evidence_tracker.append({
            "node": evidence_node,
            "id": event_id,
            "type": event_type,
            "system_uri": system_uri,
        })

    # Validate against SHACL policies
    shacl_graph = Graph()
    try:
        shacl_graph.parse(str(policy_file), format="turtle")
    except Exception as e:
        print(f"Warning: Could not load policy file: {e}")
    
    conforms, results_graph, results_text = validate(
        data_graph,
        shacl_graph=shacl_graph,
        ont_graph=None,
        inference='rdfs',
        debug=False
    )
    
    # Extract SHACL violation messages and attach to evidence nodes
    # This enables the "why" explanation in drift detection
    violation_messages = {}
    for result in results_graph.subjects(RDF.type, SH.ValidationResult):
        focus_node = results_graph.value(result, SH.focusNode)
        message = results_graph.value(result, SH.resultMessage)
        if focus_node and message:
            # Store message on the evidence node for later querying
            data_graph.add((focus_node, PACT.violationMessage, Literal(str(message))))
            violation_messages[str(focus_node)] = str(message)

    # Generate Assessment Records
    timestamp_str = timestamp.isoformat()
    
    for item in evidence_tracker:
        event_type = item['type']
        target_control = resolve_control_uri(event_type)
        
        # Filter by framework if specified
        if target_frameworks:
            control_name = str(target_control).split("#")[-1]  # e.g., "Control_AC3"
            # Normalize control name: Control_AC3 -> ac3
            normalized_control = control_name.lower().replace("control_", "").replace("-", "").replace("_", "")
            # Check if any target framework matches this control
            is_targeted = any(
                # Normalize framework: "NIST AC-3" -> "nistac3", "AC-3" -> "ac3"
                normalized_control in tf.lower().replace("-", "").replace("_", "").replace(" ", "") or
                tf.lower().replace("-", "").replace("_", "").replace(" ", "") in normalized_control
                for tf in target_frameworks
            )
            if not is_targeted:
                continue

        assessment_node = BNode()
        data_graph.add((assessment_node, RDF.type, PACT.ComplianceAssessment))
        data_graph.add((assessment_node, RDFS.label, Literal(f"Check for {item['id']}")))
        data_graph.add((assessment_node, PACT.generatedAt, Literal(timestamp_str, datatype=XSD.dateTime)))
        data_graph.add((assessment_node, PACT.evaluatedEvidence, item['node']))
        data_graph.add((assessment_node, PACT.validatesControl, target_control))
        data_graph.add((assessment_node, PACT.scanId, Literal(str(scan_uuid))))

        # Check if evidence node is in SHACL violations
        is_failure = (None, SH.focusNode, item['node']) in results_graph
        verdict = "FAIL" if is_failure else "PASS"
        data_graph.add((assessment_node, PACT.hasVerdict, Literal(verdict)))

    return str(scan_uri), data_graph
