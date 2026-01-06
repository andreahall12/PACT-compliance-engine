# PACT Demo Setup Guide

This guide explains how to prepare the PACT environment for a demo presentation.

---

## Prerequisites

### Required
- Python 3.10+
- PACT repository cloned
- Virtual environment set up

### Recommended (for AI Auditor)
- Ollama installed ([ollama.com](https://ollama.com))
- Model pulled: `ollama pull granite3.3:8b`

---

## Quick Start

### 1. Start Ollama (for AI Auditor)

```bash
# In a separate terminal
ollama serve

# Verify it's running
curl http://localhost:11434/api/version
```

### 2. Start PACT Server

```bash
cd /path/to/pact
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8002
```

### 3. Verify Dashboard

Open http://localhost:8002/visualize in your browser.

Login with:
- Email: `admin@pact.io`
- Password: `Admin@123!`

---

## Demo Data Setup

### Option A: Use Existing Demo Data

If the database already has demo data, you're good to go. Check by:

1. Login to dashboard
2. Look at Blast Radius table—should have some entries
3. Look at Systems—should see Payment Gateway, HR Portal, etc.

### Option B: Fresh Start with Demo Data

If you need to reset to a clean demo state:

```bash
# Stop the server first

# Remove existing database (will regenerate on startup)
rm db/pact.db

# Clear knowledge graph history (optional)
rm db/pact_history.trig

# Restart server
uvicorn app.main:app --host 0.0.0.0 --port 8002
```

The server will auto-create a default admin user and print the temporary password.

### Option C: Load Demo Events Manually

After starting the server, run these curl commands to populate demo data:

```bash
# Get auth token
TOKEN=$(curl -s -X POST http://localhost:8002/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@pact.io","password":"Admin@123!"}' | jq -r .access_token)

# Create demo systems
curl -X POST http://localhost:8002/v1/systems \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "payment-gateway",
    "display_name": "Payment Gateway",
    "description": "Handles credit card transactions",
    "environment": "production",
    "criticality": "critical"
  }'

curl -X POST http://localhost:8002/v1/systems \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "hr-portal",
    "display_name": "HR Portal",
    "description": "Employee management system",
    "environment": "production",
    "criticality": "high"
  }'

curl -X POST http://localhost:8002/v1/systems \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "customer-database",
    "display_name": "Customer Database",
    "description": "Customer records and PII",
    "environment": "production",
    "criticality": "critical"
  }'

# Ingest some failing events (for blast radius)
curl -X POST http://localhost:8002/v1/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "type": "file_access",
        "file": "/etc/shadow",
        "permission": "0644",
        "system": "payment-gateway"
      },
      {
        "type": "file_access",
        "file": "/app/config/secrets.yaml",
        "permission": "0777",
        "system": "hr-portal"
      },
      {
        "type": "network_connection",
        "port": 23,
        "protocol": "tcp",
        "system": "payment-gateway"
      }
    ]
  }'

# Wait a moment, then ingest more events to show drift
sleep 5

curl -X POST http://localhost:8002/v1/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "type": "file_access",
        "file": "/etc/passwd",
        "permission": "0644",
        "system": "customer-database"
      }
    ]
  }'

echo "Demo data loaded!"
```

---

## Verify Demo Is Ready

### Checklist

- [ ] Dashboard loads at http://localhost:8002/visualize
- [ ] Can login with admin@pact.io
- [ ] Dashboard shows Critical Failures table with entries
- [ ] Click "Blast Radius" in sidebar → visual diagram renders
- [ ] Click "Config Drift" in sidebar → timeline + detail cards render
- [ ] Drift cards show WHAT/WHEN/WHO/WHY details
- [ ] "Ask AI" button on drift cards works
- [ ] AI Auditor responds to questions

### Test the AI Auditor

```bash
curl -X POST http://localhost:8002/v1/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "What systems are currently failing?"}'
```

Should return a meaningful response about compliance failures.

---

## Demo Reset Script

Save this as `demo/reset_demo.sh`:

```bash
#!/bin/bash
# PACT Demo Reset Script
# Run this before each demo to ensure clean state

set -e

echo "Resetting PACT demo environment..."

# Stop any running server
pkill -f "uvicorn app.main" 2>/dev/null || true

# Remove database
rm -f db/pact.db
echo "  Removed database"

# Clear graph history
rm -f db/pact_history.trig
echo "  Cleared graph history"

# Wait a moment
sleep 2

# Start server in background
echo "Starting server..."
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8002 &
SERVER_PID=$!

# Wait for server to start
sleep 5

# Get token (using default admin that was just created)
# Note: password will be printed to console on first start
echo "Server started. Check console for temporary admin password."
echo ""
echo "To complete setup:"
echo "1. Login with the temporary password shown in console"
echo "2. Run the demo data setup commands from setup.md"
echo ""
echo "Or run: ./demo/load_demo_data.sh after logging in"
```

Make it executable:

```bash
chmod +x demo/reset_demo.sh
```

---

## Troubleshooting

### "Connection refused" on port 8002

Server isn't running. Start it with:
```bash
uvicorn app.main:app --port 8002
```

### "401 Unauthorized" on API calls

Token expired or invalid. Re-login:
```bash
TOKEN=$(curl -s -X POST http://localhost:8002/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@pact.io","password":"Admin@123!"}' | jq -r .access_token)
```

### AI Auditor returns errors

Check Ollama is running:
```bash
curl http://localhost:11434/api/version
```

If not, start it:
```bash
ollama serve
```

### No data in tables

Ingest some demo events (see Option C above).

### Slow AI responses

First query loads the model into memory. Subsequent queries will be faster. Budget ~30 seconds for first response.

---

## Environment Variables (Optional)

```bash
# For OpenAI instead of Ollama
export OPENAI_API_KEY="sk-..."
export AI_MODEL="gpt-4"

# For debugging
export DEBUG=true

# For production
export CORS_ALLOW_ORIGINS="https://your-domain.com"
```

---

## Demo Day Checklist

### 30 Minutes Before

- [ ] Start Ollama (`ollama serve`)
- [ ] Start PACT server
- [ ] Login to dashboard
- [ ] Verify demo data exists
- [ ] Test one AI question
- [ ] Close unnecessary browser tabs
- [ ] Turn off notifications

### 5 Minutes Before

- [ ] Dashboard open and logged in
- [ ] Slides ready (if using)
- [ ] This script.md open for reference
- [ ] Backup questions ready

### During Demo

- [ ] Speak slowly
- [ ] Pause for reactions
- [ ] If something breaks, acknowledge and move on

---

*Setup guide last updated: January 2026*

