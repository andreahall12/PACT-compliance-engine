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
os.environ["PACT_API_KEY"] = "test-api-key"

from app.main import app
from app.core.store import PACTStore

client = TestClient(app)
AUTH_HEADERS = {"X-API-Key": os.environ["PACT_API_KEY"]}

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
    response = client.get("/", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert response.json() == {"message": "PACT Compliance Engine is Running. Access docs at /docs"}

def test_unauthorized_without_api_key():
    # Global middleware should protect ALL routes when PACT_API_KEY is set.
    res1 = client.get("/")
    assert res1.status_code == 401
    assert "detail" in res1.json()

    res2 = client.get("/v1/compliance/stats")
    assert res2.status_code == 401
    assert "detail" in res2.json()

def test_unauthorized_with_wrong_api_key():
    res = client.get("/", headers={"X-API-Key": "wrong-key"})
    assert res.status_code == 401
    assert "detail" in res.json()

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
        
        request_body = {
            "events": VALID_EVENTS,
            "target_systems": [],
            "target_frameworks": []
        }
        response = client.post("/v1/ingest", json=request_body, headers=AUTH_HEADERS)
        if response.status_code != 200:
            print(f"Error Response: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "scan_id" in data
        assert data["triples_generated"] > 0

        # Verify stats
        stats_response = client.get("/v1/compliance/stats", headers=AUTH_HEADERS)
        assert stats_response.status_code == 200
        stats = stats_response.json()
        assert stats["total_graphs"] >= 1

def test_blast_radius(test_db):
    with patch("app.api.v1.endpoints.compliance.db", test_db):
        response = client.get("/v1/compliance/blast-radius", headers=AUTH_HEADERS)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_drift(test_db):
    with patch("app.api.v1.endpoints.compliance.db", test_db):
        response = client.get("/v1/compliance/drift", headers=AUTH_HEADERS)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_threats(test_db):
    with patch("app.api.v1.endpoints.compliance.db", test_db):
        response = client.get("/v1/compliance/threats", headers=AUTH_HEADERS)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

def test_targeted_ingest_system_filter(test_db):
    with patch("app.api.v1.endpoints.ingest.db", test_db):
        events = [
            {
                "id": "hr-event",
                "type": "file_access",
                "system": "HRPortal",
                "file": {"name": "hr.txt", "path": "/"},
                "user": {"name": "alice"}
            },
            {
                "id": "pay-event",
                "type": "file_access",
                "system": "PaymentGateway",
                "file": {"name": "pay.txt", "path": "/"},
                "user": {"name": "bob"}
            }
        ]
        # Only target HRPortal
        request_body = {
            "events": events,
            "target_systems": ["HRPortal"],
            "target_frameworks": []
        }
        response = client.post("/v1/ingest", json=request_body, headers=AUTH_HEADERS)
        assert response.status_code == 200
        
        # Verify only 1 assessment record was created
        # We can check the blast radius for HRPortal
        with patch("app.api.v1.endpoints.compliance.db", test_db):
            blast_res = client.get("/v1/compliance/blast-radius", headers=AUTH_HEADERS)
            data = blast_res.json()
            systems = [r["system"] for r in data]
            assert "HRPortal" in systems
            assert "PaymentGateway" not in systems

def test_chat_no_question():
    response = client.post("/v1/chat", json={}, headers=AUTH_HEADERS)
    assert response.status_code == 400
