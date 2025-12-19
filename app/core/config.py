import os
from pathlib import Path

# Base directory of the project (parent of 'app')
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Data Directories
DATA_DIR = BASE_DIR / "data"
CONTEXT_DIR = DATA_DIR / "context"
INPUT_DIR = DATA_DIR / "input"
MAPPINGS_DIR = DATA_DIR / "mappings"
ONTOLOGY_DIR = DATA_DIR / "ontology"
POLICIES_DIR = DATA_DIR / "policies"

# Database Directory
DB_DIR = BASE_DIR / "db"
DB_FILE = DB_DIR / "pact_history.trig"

# File Paths
SYSTEM_CONTEXT_FILE = CONTEXT_DIR / "system_context.ttl"
POLICY_RULES_FILE = POLICIES_DIR / "policy_rules.ttl"
CONTROLS_FILE = POLICIES_DIR / "controls.ttl"
FRAMEWORK_MAPPINGS_FILE = MAPPINGS_DIR / "framework_mappings.ttl"
THREAT_MAPPINGS_FILE = MAPPINGS_DIR / "threat_mappings.ttl"
PACT_ONTOLOGY_FILE = ONTOLOGY_DIR / "pact_ontology.ttl"

# Ensure DB directory exists
os.makedirs(DB_DIR, exist_ok=True)
