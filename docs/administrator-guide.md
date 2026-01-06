# PACT Administrator Guide

This guide covers installation, configuration, user management, and maintenance of the PACT (Policy Automation and Compliance Traceability) system.

---

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [User Management](#user-management)
4. [Role-Based Access Control](#role-based-access-control)
5. [System Management](#system-management)
6. [Security Best Practices](#security-best-practices)
7. [Monitoring & Maintenance](#monitoring--maintenance)
8. [Backup & Recovery](#backup--recovery)
9. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.10 or higher
- 4GB RAM minimum (8GB recommended for production)
- 10GB disk space for database and logs
- Network access to log sources (Splunk, CloudTrail, etc.)

### Option 1: Standard Installation

```bash
# Clone the repository
git clone https://github.com/your-org/pact.git
cd pact

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Option 2: Docker Installation

```bash
docker pull your-org/pact:latest
docker run -d -p 8002:8002 \
  -e DATABASE_URL="sqlite:///./db/pact.db" \
  -e JWT_SECRET_KEY="your-secure-secret" \
  your-org/pact:latest
```

### First-Time Setup

1. **Start the server:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8002
   ```

2. **Bootstrap the first admin user:**
   ```bash
   curl -X POST http://localhost:8002/v1/auth/bootstrap \
     -H "Content-Type: application/json" \
     -d '{
       "email": "admin@yourcompany.com",
       "password": "YourSecurePassword123!",
       "full_name": "System Administrator"
     }'
   ```

3. **Access the dashboard:**
   Navigate to `http://localhost:8002/visualize/`

---

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | Database connection string | `sqlite:///./db/pact.db` | No |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Auto-generated | **Yes (production)** |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiry | `15` | No |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiry | `7` | No |
| `OPENAI_API_KEY` | OpenAI API key for AI Auditor | None | No |
| `OLLAMA_HOST` | Local Ollama server URL | `http://localhost:11434` | No |
| `AI_MODEL` | AI model to use | `granite3.3:8b` | No |
| `ENABLE_DOCS` | Enable Swagger/ReDoc | `true` | No |
| `CORS_ORIGINS` | Allowed CORS origins | `*` | No |

### Example Production Configuration

```bash
export DATABASE_URL="postgresql://user:pass@localhost:5432/pact"
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
export ENABLE_DOCS=false
export CORS_ORIGINS="https://pact.yourcompany.com"
```

### Database Configuration

**SQLite (Development):**
```
DATABASE_URL=sqlite:///./db/pact.db
```

**PostgreSQL (Production):**
```
DATABASE_URL=postgresql://user:password@host:5432/pact
```

### AI Auditor Configuration

**Option 1: Local AI (Ollama) - Recommended for Privacy**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model
ollama pull granite3.3:8b

# Configure PACT
export OLLAMA_HOST=http://localhost:11434
export AI_MODEL=granite3.3:8b
```

**Option 2: OpenAI API**
```bash
export OPENAI_API_KEY=sk-your-api-key
export AI_MODEL=gpt-4
```

---

## User Management

### Creating Users

**Via API:**
```bash
curl -X POST http://localhost:8002/v1/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@company.com",
    "password": "SecurePassword123!",
    "full_name": "New User",
    "role": "security_engineer"
  }'
```

**Via Dashboard:**
1. Navigate to **Users** in the sidebar
2. Click **Add User**
3. Fill in email, name, password, and role
4. Click **Create**

### Available Roles

| Role | Code | Description |
|------|------|-------------|
| Administrator | `admin` | Full system access |
| Compliance Officer | `compliance_officer` | Policy management, full compliance view |
| Security Engineer | `security_engineer` | Technical remediation, vulnerability tracking |
| Developer | `developer` | Code-related compliance, CI/CD integration |
| System Owner | `system_owner` | Manage owned systems only |
| CISO | `ciso` | Executive dashboards, risk overview |
| Internal Auditor | `internal_auditor` | Read-only access to all data |
| External Auditor | `external_auditor` | Limited read-only access |
| Product Manager | `product_manager` | Product compliance, release gates |

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Deactivating Users

```bash
curl -X DELETE http://localhost:8002/v1/users/{user_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

This performs a soft delete, preserving audit history.

---

## Role-Based Access Control

### Permission Matrix

| Permission | Admin | Compliance | Security | Developer | System Owner | CISO | Auditors |
|------------|-------|------------|----------|-----------|--------------|------|----------|
| `users.create` | ✓ | | | | | | |
| `users.read` | ✓ | ✓ | | | | ✓ | ✓ |
| `users.update` | ✓ | | | | | | |
| `users.delete` | ✓ | | | | | | |
| `systems.create` | ✓ | ✓ | | | | | |
| `systems.read` | ✓ | ✓ | ✓ | ✓ | Own | ✓ | ✓ |
| `systems.update` | ✓ | ✓ | ✓ | | Own | | |
| `systems.delete` | ✓ | | | | | | |
| `policies.create` | ✓ | ✓ | | | | | |
| `policies.read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `documents.upload` | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| `documents.read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ai.chat` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `export.oscal` | ✓ | ✓ | | | | ✓ | ✓ |

### Assigning Teams

Users can be assigned to teams for granular access:

```bash
curl -X PATCH http://localhost:8002/v1/users/{user_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"team_ids": [1, 2, 3]}'
```

---

## System Management

### Registering Systems

Systems represent the IT assets being monitored:

```bash
curl -X POST http://localhost:8002/v1/systems \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "payment-gateway-prod",
    "display_name": "Payment Gateway (Production)",
    "description": "Handles credit card transactions",
    "environment": "production",
    "criticality": "critical",
    "data_classifications": ["pci", "pii"]
  }'
```

### System Lifecycle

```
PLANNED → ACTIVE → DEPRECATED → ARCHIVED
```

**Deprecate a system:**
```bash
curl -X POST http://localhost:8002/v1/systems/{id}/deprecate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Migrating to new platform",
    "scheduled_archive_date": "2026-06-01",
    "notify_owner": true
  }'
```

### Vendor Management

Track third-party vendors and their compliance status:

```bash
curl -X POST http://localhost:8002/v1/vendors \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_id": "aws-cloud",
    "name": "Amazon Web Services",
    "category": "iaas",
    "risk_level": "medium",
    "soc2_status": "compliant",
    "contract_end_date": "2027-01-01"
  }'
```

---

## Security Best Practices

### Production Checklist

- [ ] Set strong `JWT_SECRET_KEY` (at least 32 bytes)
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Restrict `CORS_ORIGINS` to your domains
- [ ] Disable Swagger docs (`ENABLE_DOCS=false`)
- [ ] Configure firewall rules
- [ ] Set up log aggregation
- [ ] Enable audit logging
- [ ] Regular security updates

### JWT Token Security

```bash
# Generate a secure secret
export JWT_SECRET_KEY=$(openssl rand -hex 32)

# Recommended token expiry times
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
export JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

### API Key Management

For CI/CD integration, use API tokens instead of passwords:

```bash
# Generate API token for a user
curl -X POST http://localhost:8002/v1/auth/api-token \
  -H "Authorization: Bearer $TOKEN"
```

### Audit Logging

All actions are logged automatically:

```bash
# View recent audit logs
curl http://localhost:8002/v1/audit \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Audit logs include:
- User ID and email
- Action performed
- Resource affected
- IP address
- User agent
- Timestamp

---

## Monitoring & Maintenance

### Health Check

```bash
curl http://localhost:8002/health
```

### Database Statistics

```bash
curl http://localhost:8002/v1/compliance/stats \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "total_triples": 225,
  "total_graphs": 17
}
```

### Scheduled Tasks

Set up cron jobs for recurring assessments:

```bash
# Run daily compliance scan at 2 AM
0 2 * * * curl -X POST http://localhost:8002/v1/ingest \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @/path/to/daily-events.json
```

### Log Rotation

Configure log rotation for production:

```bash
# /etc/logrotate.d/pact
/var/log/pact/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
```

---

## Backup & Recovery

### Database Backup

**SQLite:**
```bash
cp db/pact.db db/pact-backup-$(date +%Y%m%d).db
```

**PostgreSQL:**
```bash
pg_dump -U pact_user pact_db > backup-$(date +%Y%m%d).sql
```

### Knowledge Graph Backup

```bash
cp db/pact_history.trig db/pact_history-backup-$(date +%Y%m%d).trig
```

### Automated Backup Script

```bash
#!/bin/bash
# backup-pact.sh

BACKUP_DIR=/backups/pact
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Database
cp db/pact.db $BACKUP_DIR/pact-$DATE.db

# Knowledge graph
cp db/pact_history.trig $BACKUP_DIR/pact_history-$DATE.trig

# Documents
tar -czf $BACKUP_DIR/documents-$DATE.tar.gz data/documents/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -mtime +30 -delete
```

### Recovery

```bash
# Stop the server
pkill -f uvicorn

# Restore database
cp backup/pact-20260101.db db/pact.db

# Restore knowledge graph
cp backup/pact_history-20260101.trig db/pact_history.trig

# Restart server
uvicorn app.main:app --host 0.0.0.0 --port 8002
```

---

## Troubleshooting

### Common Issues

#### "Invalid email or password"
- Verify user exists: Check Users page in dashboard
- Reset password via admin API
- Check if account is locked due to failed attempts

#### "Permission denied"
- Verify user role has required permission
- Check if accessing resources outside their scope
- Review Role-Based Access Control section

#### Server won't start
```bash
# Check for port conflicts
lsof -i :8002

# Check Python environment
which python
python --version

# Verify dependencies
pip install -r requirements.txt
```

#### Knowledge graph empty
```bash
# Check if graph file exists
ls -la db/pact_history.trig

# Verify graph loading in logs
grep "Loaded.*Named Graphs" server.log
```

#### AI Auditor not responding
```bash
# Check Ollama is running
curl http://localhost:11434/api/version

# Or verify OpenAI key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

### Getting Help

- **Documentation**: Check `/docs` endpoint for API reference
- **Logs**: Review server logs for error details
- **Support**: Contact support@yourcompany.com

---

## Appendix: API Quick Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/login` | POST | User authentication |
| `/v1/auth/bootstrap` | POST | Create first admin |
| `/v1/users` | GET/POST | List/create users |
| `/v1/systems` | GET/POST | List/create systems |
| `/v1/compliance/blast-radius` | GET | Get compliance failures |
| `/v1/compliance/drift` | GET | Get configuration drift |
| `/v1/ingest` | POST | Ingest security events |
| `/v1/export/oscal` | GET | Export OSCAL report |
| `/v1/chat` | POST | AI Auditor query |

Full API documentation: `http://localhost:8002/docs`

