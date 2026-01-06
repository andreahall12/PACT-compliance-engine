# PACT Glossary

Plain-English explanations of technical terms used in PACT and the compliance ecosystem.

---

## Core Concepts

### UCO (Unified Cyber Ontology)

**What it is:** An open standard that defines a common vocabulary for cybersecurity data.

**Why it matters:** Different tools call the same things by different names. Splunk might call it a "src_ip" while CloudTrail calls it "sourceIPAddress." UCO normalizes these into a standard definition so tools can understand each other.

**Analogy:** Think of UCO like a universal translator. It doesn't matter if the original data came from AWS, Azure, or your on-prem SIEM—UCO makes sure "file" means "file" everywhere.

**Example:** A file access event from Splunk and a file access event from AWS CloudTrail both become the same UCO "Observable:File" object in PACT.

---

### SHACL (Shapes Constraint Language)

**What it is:** A W3C standard for defining rules that validate data.

**Why it matters:** Regulations are written in English ("the system shall enforce least privilege"). SHACL turns that into machine-readable rules that can be automatically checked.

**Analogy:** SHACL is like a grammar checker for compliance data. Just like spell check validates your document against language rules, SHACL validates your evidence against compliance rules.

**Example:** A SHACL rule might say "every file in /etc must have permissions 0600 or stricter." PACT runs that rule against evidence and returns PASS or FAIL.

**Who creates SHACL?** In our ecosystem, **Gemara** compiles regulatory guidance into SHACL rules.

---

### Knowledge Graph

**What it is:** A database that stores information as a network of relationships, not rows and columns.

**Why it matters:** Compliance isn't just "this control passed." It's "this control failed, which affects this system, which supports this business process, which is owned by this team." A knowledge graph captures all those connections.

**Analogy:** Think of it like a mind map instead of a spreadsheet. Everything is connected to everything else, and you can follow the links to understand context.

**Example:** In PACT's knowledge graph, you can trace: `Failed Control` → `Payment Gateway` → `Credit Card Processing` → `PCI-DSS Requirement 7.1`

---

### RDF (Resource Description Framework)

**What it is:** The underlying data format for knowledge graphs. Everything is stored as "triples": Subject → Predicate → Object.

**Why it matters:** RDF is a W3C standard, meaning PACT's data is interoperable with other tools that speak RDF.

**Analogy:** If a spreadsheet stores data in rows, RDF stores data in relationships. "The Payment Gateway" → "supports" → "Credit Card Processing" is one triple.

**You don't need to know this deeply** to use PACT. It's the plumbing under the hood.

---

### SPARQL

**What it is:** The query language for knowledge graphs (like SQL is for databases).

**Why it matters:** When PACT needs to find "all failing controls that affect PCI-DSS," it runs a SPARQL query against the knowledge graph.

**Analogy:** SPARQL is SQL for graphs. Instead of "SELECT * FROM controls WHERE status = 'FAIL'", you write pattern-matching queries that follow relationships.

**You don't need to write SPARQL** to use PACT. The AI Auditor translates your English questions into SPARQL behind the scenes.

---

### Named Graph

**What it is:** A way to group triples together with a label (usually a timestamp).

**Why it matters:** Every time PACT runs a compliance scan, it creates a new named graph. This means we can compare "what was true on Monday" vs. "what's true today" and detect drift.

**Analogy:** Think of each named graph like a timestamped snapshot. You can look back at any previous snapshot to see what the compliance state was at that moment.

---

## Ecosystem Components

### Gemara

**What it is:** A policy compiler that turns regulatory text into executable SHACL rules.

**Role in ecosystem:** Gemara is the "author" side. It reads NIST 800-53, PCI-DSS, or ISO 27001 and produces machine-readable rules.

**Relationship to PACT:** Gemara writes the rules → PACT executes them.

---

### PACT (Policy Automation and Compliance Traceability)

**What it is:** A compliance engine that ingests security evidence, runs validation rules, and produces audit-ready findings.

**Role in ecosystem:** PACT is the "runtime"—the engine that executes rules against live data.

**Key capabilities:**
- Ingest events (via UCO format)
- Run SHACL rules (from Gemara)
- Store results in a knowledge graph
- Export OSCAL reports
- Answer questions via AI

---

### OSCAL (Open Security Controls Assessment Language)

**What it is:** A NIST standard for representing compliance data in machine-readable format.

**Why it matters:** Instead of sending auditors a Word doc, you send them an OSCAL file. It's the standard format for FedRAMP, eMASS, and other regulatory systems.

**Analogy:** OSCAL is like PDF for compliance—a format everyone agreed on so documents are portable and consistent.

**What PACT exports:** OSCAL Assessment Results (SAR), which contains findings, evidence links, and control status.

---

### ComplyTime

**What it is:** A governance lifecycle platform that manages policies, attestations, and compliance programs.

**Role in ecosystem:** ComplyTime is the "home" for the compliance program—where policies are managed and stakeholders collaborate.

**Relationship to PACT:** PACT exports OSCAL → ComplyTime ingests it. PACT provides the evidence engine; ComplyTime provides the governance context.

---

## PACT-Specific Terms

### Blast Radius

**What it is:** The scope of impact when a control fails.

**Why it matters:** A single misconfiguration doesn't just fail one control—it might affect multiple frameworks, multiple business processes, and multiple systems.

**Example:** A file permission issue on the Payment Gateway might violate NIST AC-3, PCI-DSS 7.1, AND ISO 27001 A.9.4.1. That's the blast radius.

---

### Configuration Drift

**What it is:** When a system that was previously compliant becomes non-compliant over time.

**Why it matters:** Systems "rot" over time. Someone changes a setting, patches introduce regressions, or configurations get overwritten. Drift detection catches these changes—and tells you WHO caused them.

**PACT shows four things for every drift event:**
- **WHAT**: The asset and control that changed
- **WHEN**: When it was passing vs. when it started failing
- **WHO**: The actor/user who caused the change (from event data)
- **WHY**: The actual SHACL violation message explaining the failure

**Example:** The HR Portal passed NIST AC-3 on Monday. On Wednesday at 3:30 PM, `alice` changed file ownership to `root`. PACT's drift detection shows the timeline, the actor, and the SHACL message: "VIOLATION: File is owned by root user."

---

### Control

**What it is:** A specific security requirement from a framework.

**Example:** NIST AC-3 (Access Enforcement), PCI-DSS 7.1 (Restrict access to cardholder data), ISO 27001 A.9.4.1 (Information access restriction).

---

### Framework

**What it is:** A collection of controls organized by a regulatory body.

**Examples:** NIST 800-53, PCI-DSS 4.0, ISO 27001, SOC 2.

---

### Cross-Walk

**What it is:** The mapping between equivalent controls in different frameworks.

**Why it matters:** If you fail NIST AC-3, you might also be failing PCI-DSS 7.1 and ISO 27001 A.9.4.1. The cross-walk shows you all the frameworks affected by a single failure.

---

### Evidence

**What it is:** The raw data that proves a control passed or failed.

**Examples:** A log file, a configuration file, a screenshot, a SIEM event.

**In PACT:** Every finding links back to the specific evidence that triggered it.

---

## AI Auditor Terms

### Grounded AI

**What it is:** An AI that answers questions based on actual data, not just general knowledge.

**Why it matters:** Regular ChatGPT might hallucinate compliance answers. PACT's AI Auditor is "grounded" in the knowledge graph—it only knows what's actually in your data.

---

### Context Injection

**What it is:** The process of pulling relevant data from the knowledge graph and feeding it to the AI before asking a question.

**How it works:** When you ask "Why is the Payment Gateway failing?", PACT first queries the graph for Payment Gateway data, then sends that context + your question to the AI.

---

## Quick Reference Card

| Term | One-Liner |
|------|-----------|
| UCO | Common vocabulary for security data |
| SHACL | Grammar checker for compliance |
| Knowledge Graph | Mind map instead of spreadsheet |
| RDF | Relationships, not rows |
| SPARQL | SQL for graphs |
| Named Graph | Timestamped snapshot |
| Gemara | Compiles regulations to rules |
| PACT | Executes rules against evidence |
| OSCAL | Standard compliance report format |
| ComplyTime | Governance lifecycle home |
| Blast Radius | Scope of impact from a failure |
| Drift | Was compliant, now isn't + WHO/WHAT/WHEN/WHY |
| Actor | The user/process that caused a change |
| Cross-Walk | One failure affects multiple frameworks |

---

*Glossary last updated: January 2026*

