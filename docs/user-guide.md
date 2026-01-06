# PACT User Guide

Welcome to PACT (Policy Automation and Compliance Traceability). This guide helps you understand how to use the PACT dashboard to monitor compliance, investigate issues, and maintain your organization's security posture.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Compliance Monitoring](#compliance-monitoring)
4. [Configuration Drift Detection](#configuration-drift-detection)
5. [Systems Management](#systems-management)
6. [Documents & Evidence](#documents--evidence)
7. [AI Auditor](#ai-auditor)
8. [Incident Management](#incident-management)
9. [Reporting & Export](#reporting--export)
10. [Role-Specific Workflows](#role-specific-workflows)

---

## Getting Started

### Logging In

1. Navigate to your PACT instance (e.g., `https://pact.yourcompany.com/visualize/`)
2. Enter your email and password
3. Click **Sign In**

![Login Screen](images/login.png)

### First-Time Login

If this is your first login:
1. You'll receive credentials from your administrator
2. After logging in, navigate to **Settings** to update your password
3. Configure your notification preferences

### Navigation

The sidebar provides quick access to all features:

| Section | Description |
|---------|-------------|
| **Dashboard** | Overview with key metrics |
| **Blast Radius** | Compliance failures and impact |
| **Config Drift** | Systems that changed state |
| **Frameworks** | Compliance frameworks (NIST, PCI, etc.) |
| **Systems** | IT assets being monitored |
| **Documents** | Policy documents and evidence |
| **Users** | User management (admin only) |
| **Settings** | Your preferences |

---

## Dashboard Overview

The dashboard provides a real-time view of your organization's compliance posture.

### Key Performance Indicators

| KPI | Description |
|-----|-------------|
| **Active Failures** | Number of controls currently failing |
| **Drift Detected** | Systems that changed from PASS to FAIL |
| **Threats Mitigated** | Vulnerabilities covered by controls |

### Filtering Data

Use the filter bar to narrow down results:

1. **System Filter**: Select specific systems to view
2. **Framework Filter**: Filter by compliance framework (NIST, PCI-DSS, etc.)
3. **Control Filter**: Focus on specific controls
4. Click **Apply** to update the view
5. Click **Clear** to reset filters

### Refreshing Data

- Click the **Refresh** button to reload the latest data
- Data is not auto-refreshed; click Refresh after ingesting new events

---

## Compliance Monitoring

### Blast Radius Analysis

The Blast Radius view shows the impact of compliance failures across your organization.

#### Understanding the Table

| Column | Description |
|--------|-------------|
| **Date** | When the failure was detected |
| **Process** | Business process affected |
| **System** | IT system with the failure |
| **Control** | Primary control that failed (e.g., NIST AC-3) |
| **Frameworks** | All frameworks impacted by this failure |
| **Asset** | Specific file, port, or resource involved |

#### Reading a Finding

Example row:
```
Dec 15, 04:35 PM | Credit Card Processing | Payment Gateway Prod | NIST CM-7 | PCI-DSS 4.0 Req 1.3 | Port 23
```

This means:
- At 4:35 PM on Dec 15, the Payment Gateway allowed traffic on port 23 (Telnet)
- This violates NIST CM-7 (Least Functionality)
- It also impacts PCI-DSS Requirement 1.3
- The Credit Card Processing business function is at risk

#### Investigating a Finding

1. Click on any row to open the **Finding Details** drawer
2. Review the control description and evidence
3. Click **View in source system** to see the original log
4. Click **Create Incident** to track remediation

### Framework Cross-Walk

PACT automatically maps failures across frameworks. When a control fails:
- **NIST AC-3** (Access Enforcement) also triggers:
  - ISO 27001 A.9.4.1
  - PCI-DSS 4.0 Req 7.1
  - SOC 2 CC6.1

This ensures you don't miss compliance gaps in any framework.

---

## Configuration Drift Detection

Drift detection identifies systems that were previously compliant but have now failed.

### Understanding Drift

| Status | Meaning |
|--------|---------|
| **PASS → FAIL** | System was compliant, now failing (critical) |
| **FAIL → PASS** | System was failing, now remediated (good) |

### Drift Table Columns

| Column | Description |
|--------|-------------|
| **System** | The affected system |
| **Control** | The control that changed |
| **Asset** | File or configuration that changed |
| **Pass Date** | When it was last compliant |
| **Fail Date** | When it started failing |

### Responding to Drift

1. Investigate the root cause
2. Check if a change was authorized
3. Create an incident if unauthorized
4. Remediate or document exception

---

## Systems Management

### Viewing Systems

Navigate to **Systems** to see all registered IT assets.

#### System Status

| Status | Description |
|--------|-------------|
| 🟢 **Active** | System is in production |
| 🟡 **Deprecated** | Being phased out |
| ⚫ **Archived** | No longer in use |

#### Filtering Systems

- Use the status dropdown to filter by lifecycle state
- Use the search box to find systems by name

### System Details

Click on a system to view:
- Basic information (name, environment, criticality)
- Owner and team assignments
- Connected business processes
- Compliance status across frameworks
- SBOM (Software Bill of Materials) if available

### Adding a New System

1. Click **Add System**
2. Fill in the required fields:
   - **System ID**: Unique identifier (e.g., `payment-gateway-prod`)
   - **Display Name**: Human-readable name
   - **Description**: What the system does
   - **Environment**: Production, Staging, Development
   - **Criticality**: Critical, High, Medium, Low
3. Click **Create**

---

## Documents & Evidence

### Document Types

| Type | Purpose |
|------|---------|
| **Policy** | Security policies and procedures |
| **Procedure** | Step-by-step operational guides |
| **Screenshot** | Evidence of configurations |
| **Attestation** | Signed compliance certifications |

### Uploading Documents

1. Navigate to **Documents**
2. Click **Upload Document**
3. Select the file
4. Fill in metadata:
   - **Title**: Document name
   - **Type**: Policy, Procedure, Screenshot, or Attestation
   - **Framework**: Which framework this supports
   - **Expiration Date**: When the document needs review
5. Click **Upload**

### Evidence Requests

Auditors can request specific evidence:

1. **Internal/External Auditors** create evidence requests
2. **System Owners** receive notifications
3. Upload the requested document
4. Mark the request as fulfilled

### Document Expiration

- Documents have expiration dates for periodic review
- You'll receive notifications when documents are expiring
- Update and re-upload documents before they expire

---

## AI Auditor

The AI Auditor helps you understand compliance data using natural language.

### Asking Questions

1. Type your question in the chat box at the bottom of the screen
2. Press Enter or click Send
3. The AI will analyze your compliance data and respond

### Example Questions

| Question | AI Will... |
|----------|------------|
| "Why is the HR Portal failing?" | Explain the specific control failure and root cause |
| "What is the blast radius of port 23 violations?" | List all systems and business processes affected |
| "Which controls are failing most often?" | Provide a summary with counts |
| "How do I remediate NIST AC-3 failures?" | Give step-by-step remediation guidance |
| "Are we compliant with PCI-DSS?" | Summarize PCI compliance status |

### Tips for Better Answers

- Be specific: "Why is Payment Gateway failing?" vs "Why is there a failure?"
- Ask about specific controls: "Explain NIST CM-7"
- Reference time periods: "What changed this week?"

### AI Limitations

- The AI only knows about data in your PACT system
- It cannot access external resources
- For complex policy questions, consult your Compliance Officer

---

## Incident Management

### Creating an Incident

When you discover a compliance issue that needs tracking:

1. Click on a finding in the Blast Radius table
2. Click **Create Incident** in the drawer
3. Fill in incident details:
   - **Title**: Brief description
   - **Severity**: Critical, High, Medium, Low
   - **Type**: Data breach, Unauthorized access, etc.
   - **Description**: Full details
4. Click **Create**

### Incident Lifecycle

```
OPEN → INVESTIGATING → CONTAINMENT → REMEDIATION → RESOLVED → CLOSED
```

### Correlation Analysis

PACT automatically correlates incidents with compliance gaps:

- View which controls were failing when the incident occurred
- Identify patterns across multiple incidents
- Measure control effectiveness over time

---

## Reporting & Export

### OSCAL Export

Export compliance data in NIST OSCAL format:

1. Navigate to **Settings** or use the API
2. Click **Export OSCAL**
3. Download the JSON file

OSCAL exports include:
- Assessment Results
- Finding details
- System information
- Evidence links

### Scheduled Reports

Work with your administrator to set up:
- Daily compliance summaries
- Weekly executive dashboards
- Monthly trend reports

---

## Role-Specific Workflows

### Compliance Officer

Your primary responsibilities:
1. **Monitor Dashboard** daily for new failures
2. **Review Drift** to catch configuration changes
3. **Manage Policies** - upload and maintain policy documents
4. **Prepare for Audits** - generate OSCAL reports
5. **Coordinate Remediation** with system owners

**Quick Actions:**
- Create framework mappings
- Set up custom policies
- Review evidence requests
- Export compliance reports

### Security Engineer

Your primary responsibilities:
1. **Investigate Failures** in the Blast Radius view
2. **Remediate Issues** by fixing configurations
3. **Track Vulnerabilities** and their mitigations
4. **Validate Fixes** by re-ingesting events

**Quick Actions:**
- Click findings to see technical details
- View source evidence links
- Check SBOM vulnerabilities
- Monitor threat mitigations

### Developer

Your primary responsibilities:
1. **Check CI/CD Status** for compliance gates
2. **Fix Code Issues** flagged by PACT
3. **Update SBOMs** when dependencies change
4. **Review Pre-Release** compliance

**Quick Actions:**
- View failures related to your systems
- Check release gate status
- Update software inventories

### System Owner

Your primary responsibilities:
1. **Monitor Your Systems** for compliance status
2. **Respond to Failures** in your owned systems
3. **Upload Evidence** when requested
4. **Manage System Lifecycle** (deprecation, etc.)

**Quick Actions:**
- Filter to view only your systems
- Respond to evidence requests
- Update system information
- Track remediation status

### CISO / Executive

Your primary responsibilities:
1. **Review Executive Dashboard** for risk overview
2. **Track Trends** in compliance posture
3. **Prepare Board Reports** using exports
4. **Approve Risk Exceptions**

**Quick Actions:**
- View high-level KPIs
- Export OSCAL for regulatory submissions
- Review incident correlation
- Monitor control effectiveness

### Internal Auditor

Your primary responsibilities:
1. **Review Compliance Status** across all systems
2. **Verify Evidence** is current and accurate
3. **Request Additional Evidence** when needed
4. **Document Audit Findings**

**Quick Actions:**
- Browse all systems (read-only)
- Review document library
- Create evidence requests
- Export audit reports

### External Auditor

Your primary responsibilities:
1. **Review Provided Evidence** in the document library
2. **Verify Control Implementation**
3. **Request Specific Evidence** through the system

**Quick Actions:**
- View compliance data (limited scope)
- Download evidence documents
- Create evidence requests
- Review OSCAL exports

---

## Tips & Best Practices

### Daily Checks
- [ ] Review the Dashboard for new failures
- [ ] Check Drift Detection for unauthorized changes
- [ ] Review any pending evidence requests

### Weekly Tasks
- [ ] Export compliance summary
- [ ] Review trend data
- [ ] Check document expirations

### Before an Audit
- [ ] Export fresh OSCAL report
- [ ] Verify all evidence is current
- [ ] Review and close any open evidence requests
- [ ] Run full compliance scan

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Esc` | Close drawer/modal |
| `Enter` | Submit form |
| `/` | Focus search box |

---

## Getting Help

### In-App Help
- Ask the **AI Auditor** for guidance
- Hover over icons for tooltips

### Documentation
- This User Guide
- [Administrator Guide](administrator-guide.md)
- [Architecture Overview](architecture.md)
- API Reference: `/docs` endpoint

### Support
Contact your organization's PACT administrator or IT support team.

---

## Glossary

| Term | Definition |
|------|------------|
| **Blast Radius** | The scope of impact when a control fails |
| **Control** | A security measure (e.g., access control, encryption) |
| **Drift** | When a system's compliance status changes over time |
| **Framework** | A compliance standard (NIST, PCI-DSS, ISO 27001) |
| **OSCAL** | Open Security Controls Assessment Language - a standard format |
| **SHACL** | Shapes Constraint Language - used for policy rules |
| **Triple** | A unit of data in the knowledge graph (subject-predicate-object) |
| **UCO** | Unified Cyber Ontology - standard data model |

---

*Last updated: January 2026*

