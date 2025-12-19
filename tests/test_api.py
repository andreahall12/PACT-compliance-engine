import os
import sys
import json
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set up environment variables before importing app
os.environ["OPENAI_API_KEY"] = "test-key"

from app.main import app
from app.core.store import PACTStore

client = TestClient(app)

# Mock data for ingestion
VALID_EVENTS = [
    {
        "id": "test-event-001",
        "type": "file_access",
        "file": {
            "name": "sensitive_config.yaml",
            "path": "/etc/config"
        },
        "user": { "name": "admin" }
    }
]

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "PACT Compliance Engine is Running. Access docs at /docs"}

@pytest.fixture
def test_db(tmp_path):
    # Create a temporary DB file
    db_file = tmp_path / "test_pact.trig"
    store = PACTStore(storage_file=str(db_file))
    return store

def test_ingest_flow(test_db):
    # Patch the global 'db' in the endpoints
    with patch("app.api.v1.endpoints.ingest.db", test_db), \
         patch("app.api.v1.endpoints.compliance.db", test_db):
        
        response = client.post("/ingest/", json=VALID_EVENTS)
        if response.status_code != 200:
            print(f"Error Response: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "scan_id" in data
        assert data["triples_generated"] > 0

        # Verify stats
        stats_response = client.get("/compliance/stats")
        assert stats_response.status_code == 200
        stats = stats_response.json()
        assert stats["total_graphs"] >= 1

def test_blast_radius(test_db):
    with patch("app.api.v1.endpoints.compliance.db", test_db):
        response = client.get("/compliance/blast-radius")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_drift(test_db):
    with patch("app.api.v1.endpoints.compliance.db", test_db):
        response = client.get("/compliance/drift")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_threats(test_db):
    with patch("app.api.v1.endpoints.compliance.db", test_db):
        response = client.get("/compliance/threats")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_chat_no_question():
    response = client.post("/chat/", json={})
    assert response.status_code == 400
