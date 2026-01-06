# PACT: Policy Automation and Compliance Traceability

**A prototype that connects Gemara, OSCAL, and ComplyTime into one evidence-driven ecosystem.**

---

## What Is PACT?

PACT is a compliance engine that turns raw security events into audit-grade, explainable compliance posture. It ingests evidence, validates it against policy rules, and answers "what failed, why, and where's the proof?"

---

## The Ecosystem

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌───────────┐
│ GEMARA  │────▶│  PACT   │────▶│  OSCAL  │────▶│ COMPLYTIME│
│ (Rules) │     │(Engine) │     │(Output) │     │(Lifecycle)│
└─────────┘     └────┬────┘     └─────────┘     └───────────┘
                     │
                ┌────┴────┐
                │   UCO   │
                │(Language)│
                └─────────┘
```

| Component | Role |
|-----------|------|
| **UCO** | Common vocabulary for security data |
| **Gemara** | Compiles regulations into executable rules |
| **PACT** | Runs rules against live evidence |
| **OSCAL** | Standard export format for auditors |
| **ComplyTime** | Governance lifecycle platform |

---

## Key Capabilities

| Capability | What It Does |
|------------|--------------|
| **Real-time ingestion** | Events become findings instantly |
| **Blast radius analysis** | One failure → see impact across frameworks |
| **Drift detection** | Catch when compliant systems regress |
| **AI explainability** | Ask questions in plain English |
| **Evidence traceability** | Every finding links to proof |
| **OSCAL export** | Audit-ready reports in standard format |

---

## The Thesis

> **Does compliance equal security?**

PACT provides the instrument to test this question with data—by correlating security incidents with compliance state and measuring which controls actually reduce risk.

---

## How Your Work Fits

| Your Work | How PACT Uses It |
|-----------|------------------|
| **Gemara** | PACT executes Gemara's SHACL rules |
| **OSCAL** | PACT exports OSCAL Assessment Results |
| **ComplyTime** | PACT feeds ComplyTime with live evidence |
| **Framework mappings** | PACT operationalizes control requirements |

---

## Prototype Status

| Component | Status |
|-----------|--------|
| Core engine | Working |
| Knowledge graph | Working |
| AI Auditor | Working |
| Demo data | Loaded |
| Gemara integration | Proof of concept |
| ComplyTime integration | Planned |

---

## Try It Yourself

**Dashboard:** http://localhost:8002/visualize  
**Test login:** admin@pact.io / Admin@123!  
**API docs:** http://localhost:8002/docs

---

## Learn More

| Resource | Description |
|----------|-------------|
| [Architecture](../docs/architecture.md) | Technical design and data flows |
| [User Guide](../docs/user-guide.md) | How to use PACT |
| [Glossary](glossary.md) | Plain-English term definitions |

---

## Questions?

*Contact: [Your Name/Email]*

---

*PACT is a prototype demonstrating the vision of connected compliance tooling.*

