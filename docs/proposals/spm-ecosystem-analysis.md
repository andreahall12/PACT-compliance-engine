# SPM Proposal: Ecosystem Context & PACT Alignment

**Source:** [Security Posture Management (Compliance and Security)](https://docs.google.com/document/d/1qB1P9BHunmxL9cVupAoUBqn7paAbGPWLva4O7VJwYcc/)  
**Captured:** 2026-05-08  
**Author of proposal:** Emily Fox et al. (Red Hat Product Security)

---

## What the Proposal Is

A Red Hat internal proposal to automate how products declare their security and compliance posture. Engineering teams write a Gemara Layer 2 YAML file mapping their product's capabilities to NIST 800-53 controls once. ComplyTime then automatically generates compliance artifacts for every other framework (PCI-DSS, Sovereignty, OSCAL, etc.) without additional engineering effort.

**Three components:**
- **Gemara** — layered policy schema (Layer 1 = what, Layer 2 = how a product implements it)
- **ComplyTime** — automation engine; ingests Gemara files, generates OSCAL and other outputs
- **PACT** (this project) — the runtime engine; executes policies continuously, ingests logs/SBOMs/VEX, generates live evidence

The proposal names all three as an ecosystem. PACT is already the runtime layer.

---

## How PACT Fits

| Proposal Component | PACT Role |
|---|---|
| Engineering teams produce Gemara Layer 2 YAML | PACT ingests the compiled SHACL rules from Gemara |
| ComplyTime generates OSCAL for governance | PACT feeds ComplyTime with live Assessment Results |
| Customers need real-time posture visibility | PACT provides the live dashboard, drift detection, and AI Auditor |
| EDA automation angle | PACT's event-driven compliance checks are the signals EDA would consume |

PACT is the missing runtime layer in the SPM proposal. The proposal describes what products should declare; PACT is what executes those declarations against live systems and produces verifiable evidence.

---

## Key Tension in the Proposal

The most substantive comment in the document (comment [j]) flags an unresolved split:

> *"We need to differentiate between how we communicate 'security and compliance as a feature' to customers vs. how customers consume this information to meet their own compliance obligations. This document focuses on the latter. The former is of greater importance for transparency."*

**Translation:**
- **What the proposal builds:** An internal metadata system for engineering teams to declare product posture (inward-facing)
- **What customers actually need:** A way to see and trust what Red Hat has done, certified, and proven — so they can design their architecture accordingly (outward-facing transparency)

PACT addresses both sides:
- The AI Auditor and dashboard answer "what does this product's compliance posture look like?" in real time — that's the customer transparency story
- The OSCAL export feeds auditors and governance tools — that's the internal/compliance reporting side

The "Beyond" section of the proposal gestures at the customer-facing side (window shopping, AWS comparison) but it's not the core design focus. This gap is worth addressing in the next iteration.

---

## Key Technical Corrections from Reviewers

**OpenShift compliance operator → CEL**  
The proposal references OpenSCAP profiles as the existing approach. Reviewers note the Compliance Operator is actively moving from SCAP to CEL-written profiles. The "inefficient OpenSCAP" framing is partially outdated.

**OpenShift inheritance model**  
The proposal states "OpenShift inherits ~90% of its compliance posture from ROSA." This is wrong. Correct model:
- OpenShift inherits OS-level controls from RHCOS and base images only
- Kube-specific code requires separate controls
- The Compliance Operator (now moving to CEL) handles OpenShift-specific posture
- Self-managed OpenShift is the baseline; managed flavors (ROSA, ARO) add environment-specific requirements on top

**RHEL pilot readiness**  
RHEL Security Group is willing and motivated to pilot. But:
- Product variants (RHIVOS, NVIDIA day 0, Hummingbird) don't have clean inheritance and are out of scope for the pilot
- Maintaining Gemara Layer 2 YAML would be distributed across all RHEL teams — needs small-scale validation first

**Ansible staffing gap**  
EDA consumption angle is compelling but producing the data is the real problem. Ansible has no compliance engineering team; the previous policy-as-code capability was deprioritized for AI. A centralized, platform-level artifact approach (rather than per-repo) is needed.

**Language/tooling support unknown**  
MCP server prototype capability against Go (OpenShift operators), RPM Spec files (RHEL), and Ansible-based installers (AAP uses ansible operator sdk) is unvalidated. Needs explicit testing before pilot selection.

---

## Strategic Value for EMEA / Customer-Facing Narrative

The Business Value section provides strong customer-facing talking points:

1. **"Window shopping for security"** — customers pre-validate product compliance before PoC, shortening sales cycles in regulated industries
2. **Transparency vs. "trust us"** — Red Hat's verified, automated compliance trail vs. competitors' opaque models
3. **Write once, map everywhere** — engineers define capabilities once; tooling auto-generates NIST, PCI, Sovereignty artifacts
4. **Active posture management via EDA** — compliance data becomes a pipeline for automated remediation, not just a document

These are directly applicable to the CRA and DORA narrative for EMEA customers. The Gemara/PACT ecosystem is Red Hat's answer to "how do you prove your products are compliant?" — not just in theory, but with working tooling.

---

## Open Questions for Emily Engagement

1. Is there a formal working group or guild for this initiative? Who should be looped in from compliance strategy?
2. Does the proposal account for the customer-facing transparency gap (comment [j])? Is that in scope for Phase 2?
3. Where does PACT fit formally — is there a path to making this an official runtime component vs. a standalone prototype?
4. Pilot product selection: RHEL has the most stable security narrative and motivated team. Ansible has the strongest EDA story but the biggest staffing gap. Which comes first?
