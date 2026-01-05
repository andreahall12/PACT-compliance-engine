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

# AI Settings
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434/v1")
AI_MODEL = os.getenv("AI_MODEL", "granite3.3:8b")

# API Security (optional)
# If set, endpoints protected with `require_api_key` will require header: X-API-Key: <PACT_API_KEY>
PACT_API_KEY = os.getenv("PACT_API_KEY")

# CORS (default is permissive for local dev; lock this down in prod)
# Examples:
#   CORS_ALLOW_ORIGINS="https://your-ui.example.com"
#   CORS_ALLOW_ORIGINS="https://a.com,https://b.com"
#   CORS_ALLOW_ORIGINS="*"
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")


def get_cors_allow_origins() -> list[str]:
    value = (CORS_ALLOW_ORIGINS or "*").strip()
    if value == "*" or value == "":
        return ["*"]
    return [o.strip() for o in value.split(",") if o.strip()]
