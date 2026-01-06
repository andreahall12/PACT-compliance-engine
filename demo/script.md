# PACT Demo Script

**Duration:** 15 minutes  
**Audience:** Product Security Compliance team (engineers, compliance PMs, director/VP)  
**Goal:** Show how PACT connects Gemara, OSCAL, and ComplyTime into one ecosystem

---

## Pre-Demo Setup

- [ ] Dashboard open at http://localhost:8002/visualize
- [ ] Logged in as admin
- [ ] Ollama running
- [ ] Demo data loaded (some passing, some failing controls)
- [ ] Slides ready (for ecosystem diagram)

---

## Section 1: Cold Open (90 seconds)

### Stage Direction
*Dashboard is already visible on screen. You're logged in.*

### Narration

> "I've been noodling on something and wanted to get your eyes on it.
>
> You know how we've got Gemara doing policy-as-code, ComplyTime handling the governance lifecycle, and we're all working with OSCAL—but right now they're kind of... islands?
>
> I built a prototype to see what happens when you connect them.
>
> Fair warning: it's rough. But I think you'll see the idea.
>
> This is PACT—Policy Automation and Compliance Traceability. Let me show you what it does."

### Key Points
- Frame as exploration, not finished product
- Acknowledge existing work (Gemara, ComplyTime, OSCAL)
- Set humble expectations

---

## Section 2: The Ecosystem (3 minutes)

### Stage Direction
*Switch to slides or show the ecosystem diagram*

### Narration

> "Before we dive in, let me show you where this fits in the bigger picture—because some of you are building Gemara and ComplyTime, and this is how it all connects."

*[Show ecosystem diagram]*

> "There are four components working together, and one shared language underneath."

#### UCO (30 seconds)

> "**UCO—the Unified Cyber Ontology**—is an open standard that defines what a 'file,' a 'user,' a 'network connection' actually *means*.
>
> Why does this matter? Because Splunk calls it one thing, CloudTrail calls it another, and your container logs call it something else. UCO normalizes all of that.
>
> Think of it like Protocol Buffers for cybersecurity evidence. It's the contract that makes interoperability possible."

#### Gemara (45 seconds)

> "**Gemara**—which some of you are building—takes high-level regulatory guidance and compiles it into executable rules.
>
> NIST 800-53 says 'The system enforces approved authorizations.' That's English. Gemara turns it into **SHACL shapes**—machine-readable constraints.
>
> For the non-engineers: SHACL is like a grammar checker for compliance data. It validates that the evidence meets the requirements.
>
> **The handoff:** Gemara produces rules → PACT executes them."

#### PACT (30 seconds)

> "**PACT is the engine.** It:
> - Ingests evidence (in UCO format)
> - Runs Gemara's SHACL rules
> - Stores results in a knowledge graph
> - Answers 'what failed, why, and where's the proof?'
>
> It's the runtime. Gemara writes the rules, PACT enforces them."

#### OSCAL (30 seconds)

> "**OSCAL**—which you're all familiar with—is how we get data *out* of PACT.
>
> When an auditor asks 'prove you're compliant,' we export an **OSCAL Assessment Results** file. This is the format FedRAMP expects. It's what ComplyTime can ingest."

#### ComplyTime (30 seconds)

> "**ComplyTime** is the governance home—where policies are managed, attestations are tracked, and the compliance program lives.
>
> PACT feeds ComplyTime with real-time evidence and OSCAL exports. ComplyTime provides the context.
>
> **The relationship:** ComplyTime is the *program*, PACT is the *evidence engine* that powers it."

### Transition

> "That's the pipeline. Now let me show you PACT actually working."

---

## Section 3: Live Demo - Trigger a Failure (2 minutes)

### Stage Direction
*Switch back to the dashboard*

### Narration

> "Let me simulate a misconfiguration event."

*[Click on the dashboard area or use curl if needed]*

**Option A: Using the UI**
> "I'm going to trigger an event that represents a file with incorrect permissions."

*[If there's a Simulate Event button, click it]*

**Option B: Using curl (backup)**
```bash
curl -X POST http://localhost:8002/v1/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "type": "file_access",
      "file": "/etc/shadow",
      "permission": "0644",
      "system": "payment-gateway"
    }]
  }'
```

> "That just ingested an event. Watch..."

*[Click Refresh or wait for auto-refresh]*

> "There it is. Real-time."

### Show the Blast Radius

*[Point to the new row in the table]*

> "Here's what I think is interesting: it doesn't just say 'failed.'
>
> Look at these columns:
> - **Process:** Credit Card Processing—that's the business function at risk
> - **System:** Payment Gateway—the specific asset
> - **Control:** NIST CM-7—Least Functionality
> - **Frameworks:** This also violates PCI-DSS 4.0 Req 1.3 AND ISO 27001 A.12.6.1
>
> One event, and we instantly see the blast radius across frameworks."

### For the Audience

> *[To engineers]* "This mapping comes from the rules—which could come from Gemara."
>
> *[To compliance]* "This is the audit trail and the business impact in one place."

---

## Section 4: Prove Traceability (2 minutes)

### Stage Direction
*Click on the evidence link or hover over it*

### Narration

> "Every finding has an evidence link. Let me show you."

*[Click the external link icon on a finding row]*

> "This isn't a status light—it's traceable proof. If an auditor asks 'where did this come from?', we point them here.
>
> The evidence is timestamped, hashed, and linked to the specific control it violated."

### If Link Doesn't Open

> "In a full deployment, this would deep-link to your SIEM or log aggregator. For the demo, it's pointing to the raw event data."

---

## Section 5: Show Drift (2 minutes)

### Stage Direction
*Scroll to or click on the Configuration Drift section*

### Narration

> "Here's something else I want to show you: drift detection."

*[Point to the drift table]*

> "This shows systems that *were* compliant but *aren't anymore*.
>
> See this row? The Payment Gateway was passing this control on Monday. Today it's failing. Something changed.
>
> This is continuous monitoring vs. point-in-time snapshots. We catch regressions as they happen—not in the next quarterly audit."

### For the Audience

> *[To VPs]* "This is how you answer 'when did we become non-compliant?' with precision."
>
> *[To engineers]* "This is why we use named graphs—each scan is timestamped and we can compare across time."

---

## Section 6: AI Auditor (2 minutes)

### Stage Direction
*Open the chat panel or scroll to the AI Auditor section*

### Narration

> "So here's the part I'm most excited about. I hooked up an AI auditor—and here's the key thing: it's grounded in the knowledge graph. It's not just freestyle GPT."

*[Type a question]*

#### Question Options (pick based on audience):

**For executives:**
> "What's the highest-impact failure and what business process does it affect?"

**For compliance:**
> "What control failed on the Payment Gateway and what evidence supports it?"

**For engineers:**
> "Why is the Payment Gateway failing and which specific asset triggered it?"

*[Wait for response]*

> "It pulled context from the graph, explained the failure, and cited the evidence. Plain English."

### Key Framing

> "This is the same data model that Gemara's rules run against. The AI is reading live compliance state—not hallucinating."

### Backup Questions (if first one doesn't land)

- "Why is the HR Portal failing?"
- "What's the blast radius of NIST AC-3 violations?"
- "Which systems are currently compliant?"

---

## Section 7: The Connection (2 minutes)

### Stage Direction
*This is the key moment. Make eye contact with specific team members.*

### Narration

> "So here's the thing: this isn't separate from what we're already building.
>
> *[To Gemara engineers]* The rules PACT runs? They're SHACL. That's Gemara's output. If we connected them, your policies become enforceable in real-time.
>
> *[To ComplyTime engineers]* The output PACT generates? It's OSCAL Assessment Results. That's what ComplyTime ingests. If we connected them, you get live evidence feeds.
>
> *[To compliance folks]* The frameworks and control mappings? That's the regulatory knowledge you maintain. PACT operationalizes it.
>
> Right now, these are separate workstreams. This prototype is a proof of concept for what happens when they're one ecosystem."

*[Let that land. Pause.]*

---

## Section 8: The Thesis (2 minutes)

### Stage Direction
*This elevates from "cool tool" to "strategic question"*

### Narration

> "One more thing. There's a question we debate a lot: Does compliance actually equal security? Or is it just checkbox theater?
>
> PACT gives us a way to test that hypothesis.
>
> If we track incidents AND compliance state, we can correlate them. We can ask:
> - Was this system 'compliant' when the incident happened?
> - Do certain controls actually prevent incidents?
> - Which controls are just paperwork vs. actually reducing risk?
>
> That's not a tool feature—that's a research question. And this prototype is the instrument to answer it."

---

## Section 9: Close (90 seconds)

### Stage Direction
*Wrap up. Open for discussion.*

### Narration

> "So that's PACT. It's rough—there's a lot I'd want to improve. But I wanted to show you the idea:
>
> A runtime that connects Gemara, OSCAL, and ComplyTime into one evidence-driven ecosystem.
>
> The key outcomes:
> - **Continuous posture** (not quarterly snapshots)
> - **Traceability** (every finding links to proof)
> - **Cross-framework mapping** (one failure → multiple requirements)
> - **Explainability** (AI that can answer 'why')
>
> I'm curious what you think. Does this resonate? What would make it more useful?"

*[Stop talking. Let them respond.]*

---

## If They Ask Follow-Up Questions

### "What would it take to make this real?"

> "Honestly, the hardest part is already done—the architecture and the proof of concept. The next step would be tighter integration with Gemara's rule output and ComplyTime's ingest. That's probably a sprint or two with the right people."

### "What's the business case?"

> "Faster audits, continuous compliance posture, and—if the thesis holds—actual evidence that our controls reduce risk. That's not a pitch, that's a research question we could answer."

### "Can I try it?"

> "Absolutely. I can share the repo and test credentials. It's running on [localhost/demo server]."

---

## Backup: Terminal-Only Demo

If the UI fails, use curl commands:

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8002/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@pact.io","password":"Admin@123!"}' | jq -r .access_token)

# Ingest event
curl -X POST http://localhost:8002/v1/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"events":[{"type":"file_access","file":"/etc/shadow","permission":"0644","system":"payment-gateway"}]}'

# Get blast radius
curl -s http://localhost:8002/v1/compliance/blast-radius \
  -H "Authorization: Bearer $TOKEN" | jq

# Ask AI
curl -X POST http://localhost:8002/v1/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question":"Why is the Payment Gateway failing?"}'
```

---

*Script last updated: January 2026*

