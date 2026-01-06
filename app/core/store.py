import os
from rdflib import Dataset, Namespace, URIRef
from rdflib.namespace import RDF, RDFS, XSD
import threading

# Namespaces
PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")
UCO_CORE = Namespace("https://ontology.unifiedcyberontology.org/uco/core/")
SH = Namespace("http://www.w3.org/ns/shacl#")

from app.core.config import DB_FILE, FRAMEWORK_MAPPINGS_FILE, THREAT_MAPPINGS_FILE

class PACTStore:
    def __init__(self, storage_file=str(DB_FILE)):
        self.storage_file = storage_file
        self.ds = Dataset()
        self.lock = threading.Lock()
        
        # Load existing data
        if os.path.exists(self.storage_file):
            print(f"Loading Graph DB from {self.storage_file}...")
            try:
                self.ds.parse(self.storage_file, format='trig')
                print(f"Loaded {sum(1 for _ in self.ds.graphs())} Named Graphs.")
            except Exception as e:
                print(f"Error loading graph: {e}")
        else:
            print("Initializing new Graph DB.")

        # Bind namespaces
        self.ds.bind("pact", PACT)
        self.ds.bind("uco-obs", UCO_OBS)
        self.ds.bind("uco-core", UCO_CORE)
        self.ds.bind("sh", SH)

        # Load Global Knowledge (Frameworks + Threats)
        self._load_ttl_if_exists(str(FRAMEWORK_MAPPINGS_FILE))
        self._load_ttl_if_exists(str(THREAT_MAPPINGS_FILE))

    def _load_ttl_if_exists(self, filename):
        if os.path.exists(filename):
            print(f"Loading Context from {filename}...")
            try:
                self.ds.parse(filename, format='turtle')
            except Exception as e:
                print(f"Error loading {filename}: {e}")

    def save(self):
        """Persist changes to disk using atomic write (temp file + rename)."""
        import tempfile
        import shutil
        
        with self.lock:
            # Write to temp file first, then rename for atomicity
            dir_name = os.path.dirname(self.storage_file) or "."
            fd, temp_path = tempfile.mkstemp(suffix=".trig", dir=dir_name)
            try:
                os.close(fd)
                self.ds.serialize(destination=temp_path, format='trig')
                shutil.move(temp_path, self.storage_file)
            except Exception:
                # Clean up temp file on failure
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise

    def add_graph(self, graph_uri, graph_data):
        """Merge a new scan (Graph) into the Dataset (thread-safe)."""
        with self.lock:
            target_graph = self.ds.graph(URIRef(graph_uri))
            
            # Add triples from the new graph data to the dataset's named graph
            for s, p, o in graph_data:
                target_graph.add((s, p, o))
        
        # Save outside the main lock to avoid holding it during I/O
        self.save()

    def query(self, sparql_query):
        """Execute SPARQL Query (thread-safe read)."""
        with self.lock:
            return list(self.ds.query(sparql_query))

    def _graph_count(self) -> int:
        """Count graphs without creating intermediate list."""
        return sum(1 for _ in self.ds.graphs())

    def get_stats(self):
        """Get store statistics (thread-safe)."""
        with self.lock:
            return {
                "total_triples": len(self.ds),
                "total_graphs": self._graph_count()
            }

# Singleton Instance
db = PACTStore()
