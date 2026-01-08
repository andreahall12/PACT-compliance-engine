# VEX Integration Design for PACT

> **Status:** Proposal  
> **Author:** Andrea Hall  
> **Date:** January 7, 2026  

## Executive Summary

PACT can be extended to ingest VEX (Vulnerability Exploitability eXchange) files and correlate them with product configuration data to determine if vulnerabilities are mitigated by how a product is deployed.

---

## Part 1: PACT VEX Integration Design

### 1.1 Goal

Enable PACT to answer: **"Is CVE-X mitigated by how our [product] cluster is configured?"**

### 1.2 Data Flow

\`\`\`
VEX Files (CSAF/OpenVEX) + Config Data ([product]) → PACT Correlation → Mitigation Verdict
\`\`\`

### 1.3 New Components

| Component | Description | Implementation |
|-----------|-------------|----------------|
| **VEX Ingester** | Parse CSAF and OpenVEX JSON files | New endpoint: POST /v1/vex/ingest |
| **Condition Extractor** | Extract mitigation conditions from VEX notes | AI-assisted NLP |
| **Config Mapper** | Map config settings to UCO observables | Extend existing event mapping |
| **Mitigation Analyzer** | Correlate VEX conditions with config state | New SHACL rules or graph queries |

---

## Part 2: Recommendations for Improving VEX Data

### 2.1 The Problem

Current VEX files have **structured status** but **unstructured mitigation conditions**.

### 2.2 Proposed Enhancement: Structured Mitigation Conditions

Add a new field mitigation_conditions with machine-readable data:

\`\`\`json
{
  "mitigation_conditions": [{
    "type": "configuration",
    "component": "selinux",
    "operator": "equals",
    "value": "enforcing",
    "description": "SELinux must be in enforcing mode"
  }]
}
\`\`\`

### 2.3 Benefits

- Automated triage - customers filter CVEs by their config
- Reduced support tickets - "Am I affected?" answered by tooling
- Compliance automation - prove mitigation status to auditors
- Security scanner integration - scanners could consume for policy enforcement

### 2.4 Implementation Path

**Phase 1:** Pilot with 10-20 high-profile CVEs
**Phase 2:** Build tooling to extract conditions
**Phase 3:** Integrate into CVE analysis workflow

---

## Part 3: Integration with Security Tools

- **Compliance scanning tools**: Consume config check results
- **Container security platforms**: Auto-create policies for unmitigated CVEs
- **Build pipeline tooling**: Build pipeline logs as evidence

---

## Summary

| Topic | Key Point |
|-------|-----------|
| **PACT Integration** | New VEX ingester + condition extractor + config mapper |
| **VEX Data Improvement** | Add structured mitigation_conditions field |
| **Value Proposition** | Automated "Am I affected?" answers |
| **Quick Win** | Pilot with 10-20 high-profile [product] CVEs |
