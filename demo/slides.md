# PACT Demo Slide Deck

Copy this content into PowerPoint, Google Slides, or Keynote.

---

## Slide 1: Title

### Visual
- **Title:** PACT: Connecting the Compliance Ecosystem
- **Subtitle:** A prototype that ties Gemara, OSCAL, and ComplyTime together
- **Footer:** [Your Name] • Product Security Compliance

### Speaker Notes
> "I've been experimenting with something and wanted to share it with you. This is a prototype called PACT—let me show you what happens when we connect our existing tools into one ecosystem."

### Timing
30 seconds

---

## Slide 2: The Problem

### Visual

| Before (Today) | After (PACT) |
|----------------|--------------|
| Regulations in PDFs | Gemara compiles to executable rules |
| Evidence in 5 different formats | UCO normalizes everything |
| Compliance = spreadsheets | PACT validates and traces |
| Audit reports = Word docs | OSCAL standard format |
| Program lives in email | ComplyTime lifecycle |

### Speaker Notes
> "This is what we're dealing with today versus what becomes possible when the pieces connect. The work you're already doing on Gemara, OSCAL, and ComplyTime becomes more valuable when there's an engine in the middle."

### Timing
45 seconds

---

## Slide 3: The Ecosystem

### Visual

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         THE PACT ECOSYSTEM                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌───────────┐        │
│   │ GEMARA  │────▶│  PACT   │────▶│  OSCAL  │────▶│ COMPLYTIME│        │
│   │ (Rules) │     │(Engine) │     │(Output) │     │(Lifecycle)│        │
│   └─────────┘     └────┬────┘     └─────────┘     └───────────┘        │
│                        │                                                │
│                   ┌────┴────┐                                           │
│                   │   UCO   │                                           │
│                   │(Language)                                           │
│                   └─────────┘                                           │
│                        ▲                                                │
│              ┌─────────┴─────────┐                                      │
│              │  Splunk / SIEM /  │                                      │
│              │  CloudTrail / etc │                                      │
│              └───────────────────┘                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Speaker Notes
> "Here's how the pieces fit:
> - UCO is the shared language that normalizes evidence from any source
> - Gemara compiles regulations into executable SHACL rules
> - PACT is the engine that runs the rules against evidence
> - OSCAL is the standard output format
> - ComplyTime is the governance home
>
> Your work becomes more valuable when connected."

### Timing
90 seconds

---

## Slide 4: Glossary (Quick Reference)

### Visual

| Term | What It Is | Analogy |
|------|------------|---------|
| **UCO** | Standard vocabulary for security data | "Common language for Splunk and CloudTrail" |
| **SHACL** | Rules that validate data | "Grammar checker for compliance" |
| **Knowledge Graph** | Database of relationships | "Mind map, not spreadsheet" |
| **OSCAL** | Standard compliance report format | "The PDF everyone agreed on" |

### Speaker Notes
> "Quick glossary for anyone less familiar with these terms. Don't worry about memorizing this—there's a reference doc I can share. The key idea: these are all open standards, not proprietary lock-in."

### Timing
30 seconds (don't dwell)

---

## Slide 5: Live Demo

### Visual

**[LIVE DEMO]**

- Trigger a compliance failure
- See the blast radius **visual diagram**
- Watch drift detection
- Ask the AI auditor

*Switching to live system...*

### Speaker Notes
> "Let me switch to the live system and show you this actually working. We'll see how one violation creates a visual blast radius across your entire compliance landscape."

### Timing
0 seconds (transition slide)

---

## Slide 6: What You Just Saw

### Visual

| Capability | What It Means |
|------------|---------------|
| **Real-time ingestion** | Events become findings instantly |
| **Visual blast radius** | Interactive diagram: Event → System → Process → Frameworks |
| **Drift detection + attribution** | WHO caused it, WHAT changed, WHEN, and WHY (SHACL message) |
| **AI explainability** | Plain English answers grounded in data |
| **Evidence traceability** | Every finding links to proof |

### Speaker Notes
> "Recap of what we just saw. The blast radius shows how one violation ripples across your compliance landscape. The drift detection doesn't just show 'something changed'—it shows WHO changed it and WHY it's a violation, using the actual SHACL message from the policy engine. This isn't quarterly reporting—it's continuous, with full attribution."

### Timing
30 seconds

---

## Slide 7: The Thesis

### Visual

# Does Compliance = Security?

**PACT lets us test this hypothesis with data.**

- Correlate incidents with compliance state
- Measure which controls actually prevent incidents
- Identify "checkbox theater" vs. real risk reduction

### Speaker Notes
> "Here's the bigger question this prototype helps us answer. We've all debated whether compliance is just theater or actually security. PACT gives us the instrument to test that—by correlating real incidents with compliance state over time.
>
> That's not a feature, that's a research question. And we could answer it."

### Timing
90 seconds

---

## Slide 8: How Your Work Fits

### Visual

| Your Work | How PACT Uses It |
|-----------|------------------|
| **Gemara** | PACT executes Gemara's SHACL rules |
| **OSCAL** | PACT exports OSCAL Assessment Results |
| **ComplyTime** | PACT feeds ComplyTime with live evidence |
| **Frameworks** | PACT operationalizes your control mappings |

### Speaker Notes
> "This isn't separate from what you're building—it connects it.
>
> Gemara engineers: your rules become enforceable in real-time.
> ComplyTime engineers: you get live evidence feeds.
> Compliance folks: your framework knowledge is operationalized.
>
> The work you're already doing becomes more valuable together."

### Timing
60 seconds

---

## Slide 9: What's Next?

### Visual

**Prototype Status:**
- Core engine: Working
- Demo data: Loaded
- AI Auditor: Functional

**To Make It Real:**
- Tighter Gemara integration (rule import)
- ComplyTime OSCAL ingest pipeline
- Production data sources (Splunk, CloudTrail)

**The Ask:** *Your feedback and ideas*

### Speaker Notes
> "This is a prototype. The architecture works, but there's more to build if we want it production-ready.
>
> I'm not asking for resources right now—I'm asking for your thoughts. Does this resonate? What would make it more useful for your work?"

### Timing
60 seconds

---

## Slide 10: Discussion

### Visual

# Questions?

**Try it yourself:**
- Dashboard: http://localhost:8002/visualize
- Test login: admin@pact.io / Admin@123!

**Materials:**
- [One-pager summary](one-pager.md)
- [Architecture docs](../docs/architecture.md)

### Speaker Notes
> "I'd love to hear your thoughts. What resonated? What's missing? What would you want to see?"

### Timing
Open-ended discussion

---

## Slide Order Summary

1. Title (30s)
2. The Problem: Before/After (45s)
3. The Ecosystem Diagram (90s)
4. Glossary Quick Reference (30s)
5. Live Demo Transition (0s)
6. What You Just Saw (30s)
7. The Thesis: Security = Compliance? (90s)
8. How Your Work Fits (60s)
9. What's Next (60s)
10. Discussion (open)

**Total slides time: ~7 minutes**
**Live demo: ~6 minutes**
**Discussion: ~2+ minutes**

---

## Design Notes

### Recommended Style
- Clean, minimal design
- Dark mode or light mode (match your team's preference)
- Use the ecosystem diagram as a recurring visual
- Avoid clip art; use simple boxes/arrows

### Fonts
- Headlines: Bold sans-serif (e.g., Inter, SF Pro, Helvetica)
- Body: Regular sans-serif
- Code: Monospace (e.g., JetBrains Mono, Fira Code)

### Colors
- Primary: Blue or teal (trust/technology)
- Accent: Orange or red for failures/alerts
- Background: White or dark gray
- Avoid: Overly corporate templates

---

*Slides last updated: January 2026*

