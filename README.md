# PACT: Pipeline for Automated Compliance Traceability

**PACT** is a Proof-of-Concept (PoC) semantic engine that bridges the gap between **Security Operations** (OCSF logs) and **Compliance Governance** (OSCAL/NIST).

Instead of relying on manual checklists, PACT ingests raw security events, maps them to a **Unified Cyber Ontology (UCO)**, and uses **SHACL** shapes to automatically validate them against federal regulations (NIST 800-53).

---

### The Architecture
PACT demonstrates a "Semantic Compliance" pipeline:
1.  **Ingest:** Reads raw JSON logs (Files & Network events) in OCSF format.
2.  **Normalize:** Lifts data into a semantic Knowledge Graph (RDF/Turtle).
3.  **Assess:** Validates the graph against logic rules (SHACL) derived from NIST controls.
4.  **Record:** Generates an immutable "Compliance Assessment" artifact.

### Pipeline Workflow
```mermaid
graph TD
    A[OCSF Log Stream] -->|Ingest| B(PACT Engine)
    C[Policy Rules SHACL] -->|Validate| B
    B -->|Generate| D[Knowledge Graph RDF]
    D -->|Query| E[Auditor Script SPARQL]
    E -->|Output| F[Unified Compliance Report]