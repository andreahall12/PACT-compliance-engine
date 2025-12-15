from rdflib import Graph, Literal, BNode, RDF, Namespace
from pyshacl import validate

# 1. Setup Namespaces (Defining our vocabulary)
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")

# 2. Ingest Data (Simulating a Raw Log)
# We are pretending we found a file owned by root
raw_log = {
    "filename": "sensitive_config.yaml",
    "owner": "admin", 
    "path": "/etc/configs/"
}

print("--- Step 1: Lifting Data to Knowledge Graph ---")

# 3. Create the Graph (The "Evidence Store")
data_graph = Graph()
file_node = BNode() # Create a blank node for the file

# We add "Triples" to the graph: (Subject, Predicate, Object)
# "This Node" IS A "File"
data_graph.add((file_node, RDF.type, UCO_OBS.File))
# "This Node" HAS OWNER "root"
data_graph.add((file_node, UCO_OBS.owner, Literal(raw_log["owner"])))
# "This Node" HAS FILENAME "sensitive_config.yaml"
data_graph.add((file_node, UCO_OBS.fileName, Literal(raw_log["filename"])))

# Show the user what the computer sees (in Turtle format)
print(data_graph.serialize(format='turtle'))

# 4. Load Policy (The Rules)
shacl_graph = Graph()
shacl_graph.parse("policy_rules.ttl", format="turtle")

# 5. Run the PACT Assessment
print("\n--- Step 2: Running PACT Validation ---")
conforms, results_graph, results_text = validate(
    data_graph,
    shacl_graph=shacl_graph,
    ont_graph=None,
    inference='rdfs',
    abort_on_first=False,
    meta_shacl=False,
    debug=False
)

# 6. Output Result
if conforms:
    print("RESULT: PASS - No violations found.")
else:
    print("RESULT: FAIL - Violations detected!")
    print("\nDetailed Report:")
    print(results_text)