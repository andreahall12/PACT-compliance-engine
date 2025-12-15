# PACT: Policy Automation and Compliance Traceability

## Overview
PACT is a Semantic Compliance Engine designed to demonstrate how **Operational Reality** (live telemetry) can be validated against **Governance Logic** using machine-readable standards.

Unlike traditional compliance scripts, PACT uses a **Declarative Architecture**:
* **Data** is lifted into a Knowledge Graph (RDF/Turtle).
* **Logic** is defined as shapes/constraints (SHACL), not code.
* **Validation** produces a traceable audit graph.

## Architecture
This Proof-of-Concept (PoC) aligns with the **UCO (Unified Cyber Ontology)** philosophy:

1.  **Ingest:** Raw logs (simulated OCSF) are converted into RDF triples.
2.  **Model:** Data is mapped to the `pact_ontology` and `uco-observable` namespaces.
3.  **Assess:** A SHACL engine (`pyshacl`) validates the data graph against `policy_rules.ttl`.
4.  **Report:** The engine outputs a standard Validation Report Graph.

## How to Run
1.  Clone the repository.
2.  Install dependencies: `pip install rdflib pyshacl`
3.  Run the engine:
    ```bash
    python3 pact_engine.py
    ```
### Pipeline Workflow - test 
```mermaid
graph TD
    A[OCSF Log JSON] -->|Ingest| B(PACT Engine)
    C[Policy Rules SHACL] -->|Validate| B
    B -->|Generate| D[Knowledge Graph RDF]
    D -->|Query| E[Auditor Script SPARQL]
    E -->|Output| F[Compliance Report]
    ```

## Files
* `pact_engine.py`: The "Lifter" and execution logic.
* `policy_rules.ttl`: The SHACL constraints (The "Law").
* `pact_ontology.ttl`: The Semantic Model (The "Language").
