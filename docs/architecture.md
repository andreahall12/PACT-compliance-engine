# PACT System Architecture

This document describes the technical architecture of **PACT** (Policy Automation and Compliance Traceability).

## 1. High-Level Ecosystem

PACT is built on a "Semantic-First" philosophy, where every security event, compliance control, and business process is represented as a node in a Knowledge Graph.

```mermaid
flowchart TD
    User((User)) <--> Frontend[Web Dashboard]
    Frontend <--> Backend[FastAPI Server]
    Backend <--> Graph[RDF Graph Store]
    Backend <--> AI[Ollama / Local AI]
    Backend <--> Gemara[Gemara MCP Server]
```

---

## 2. Core Components

### **A. API Layer (`app/api/v1/`)**
A modular FastAPI application providing versioned endpoints for:
-   **`/ingest`**: Entry point for security logs.
-   **`/compliance`**: Retrieval of blast radius, drift, and threat data.
-   **`/chat`**: Interface for the AI Auditor.
-   **`/visualize`**: Serving the dashboard UI.

### **B. Compliance Engine (`app/core/engine.py`)**
The "Brain" of PACT. It maps incoming JSON data to the **Unified Cyber Ontology (UCO)** and executes **SHACL (Shapes Constraint Language)** rules to determine compliance status.

### **C. Semantic Store (`app/core/store.py`)**
A persistent RDF Graph database powered by **RDFLib**. 
-   **Format**: TriG (Triples in Graphs).
-   **Temporal Tracking**: Every scan is stored in a unique **Named Graph**, allowing PACT to detect "Drift" by comparing graphs across time.

### **D. AI Auditor (`app/api/v1/endpoints/chat.py`)**
A hybrid inference client that uses **SPARQL** to pull context from the graph and injects it into a LLM prompt. It supports:
-   **Local Mode**: Direct HTTP communication with **Ollama** (Model: `granite3.3:8b`).
-   **Cloud Mode**: Integration with **OpenAI GPT-4o**.
-   **MCP Integration**: Connects to the **Gemara MCP Server** to use specialized GRC tools.

---

## 3. Data Flow Diagrams

### **Ingestion & Validation Pipeline**
This flow transforms raw logs into actionable compliance intelligence.

```mermaid
sequenceDiagram
    participant SIEM as SIEM (Splunk/JSON)
    participant API as PACT API (/ingest)
    participant Engine as Compliance Engine
    participant SHACL as PySHACL Validator
    participant DB as RDF Store (TriG)

    SIEM->>API: Send JSON Event
    API->>Engine: run_assessment(events)
    Engine->>Engine: Map to UCO/RDF Triples
    Engine->>SHACL: Validate against Policy Rules
    SHACL-->>Engine: Returns Compliance Result (PASS/FAIL)
    Engine->>DB: Save Scan to Named Graph
    API-->>SIEM: HTTP 200 (Success)
```

### **AI Auditor Query Flow**
How PACT answers questions like *"Why is the Payment Gateway failing?"*

```mermaid
flowchart TD
    Q[User Question] --> API[FastAPI Chat Endpoint]
    API --> SPARQL[SPARQL Context Query]
    SPARQL --> DB[(RDF Store)]
    DB --> Context[JSON Context Data]
    Context --> Prompt[System Prompt + Context + Question]
    Prompt --> LLM{AI Provider}
    LLM --> Ollama[Local Ollama]
    LLM --> OpenAI[Cloud OpenAI]
    Ollama --> Response[Markdown Answer]
    OpenAI --> Response
    Response --> API
    API --> Result[Final Answer to User]
```

---

## 4. Semantic Data Model

PACT uses a specialized ontology extending **UCO** to link technical evidence to regulatory requirements.

```mermaid
classDiagram
    class ComplianceAssessment {
        +datetime generatedAt
        +string verdict (PASS/FAIL)
    }
    class Control {
        +string label
        +string requirementID
    }
    class Evidence {
        +uri sourceUrl
    }
    class System {
        +string label
    }
    class Requirement {
        +string identifier
    }

    ComplianceAssessment --> Control : validates
    ComplianceAssessment --> Evidence : evaluated
    System --> Evidence : hasComponent
    Control --> Requirement : satisfies
```

---

## 5. Technology Stack

| Category | Technology |
| :--- | :--- |
| **Language** | Python 3.14+ |
| **Web Framework** | FastAPI / Uvicorn |
| **Knowledge Graph** | RDFLib (SPARQL 1.1) |
| **Policy Language** | W3C SHACL |
| **AI (Local)** | Ollama (IBM Granite 3.3) |
| **AI (Cloud)** | OpenAI (GPT-4o) |
| **Protocol** | Model Context Protocol (MCP) |
| **Governance** | Gemara Policy Compiler |
