# PACT Demo Package

This folder contains everything you need to demo PACT to your team.

---

## Quick Start

### 1. Pre-Demo Checklist

- [ ] PACT server running (`uvicorn app.main:app --port 8002`)
- [ ] Ollama running (`ollama serve`) with model pulled (`ollama pull granite3.3:8b`)
- [ ] Dashboard loaded at http://localhost:8002/visualize
- [ ] Logged in with test credentials (admin@pact.io / Admin@123!)
- [ ] Demo data populated (see [setup.md](setup.md))
- [ ] Rehearsed at least once
- [ ] Backup questions ready for AI Auditor

### 2. Demo Duration

**Target: 15 minutes** (can extend to 20 with Q&A)

| Section | Time | What Happens |
|---------|------|--------------|
| Cold Open | 90s | Set the stage, show dashboard |
| The Ecosystem | 3 min | Gemara → PACT → OSCAL → ComplyTime |
| Live Demo | 6 min | Trigger failure, blast radius, drift, AI |
| The Thesis | 2 min | Security = Compliance? |
| Close | 90s | Discussion, next steps |

### 3. Materials

| File | Purpose |
|------|---------|
| [script.md](script.md) | Full narration with timing |
| [slides.md](slides.md) | Slide content + speaker notes |
| [glossary.md](glossary.md) | Plain-English term explainers |
| [one-pager.md](one-pager.md) | Leave-behind summary |
| [setup.md](setup.md) | Environment setup + data reset |

---

## Before You Present

### Environment Setup

```bash
# Terminal 1: Start PACT
cd /path/to/pact
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8002

# Terminal 2: Ensure Ollama is running
ollama serve
```

### Reset Demo Data

Before each demo, reset to a clean state:

```bash
# Run the demo data reset script
./demo/reset_demo.sh
```

Or manually:
1. Delete `db/pact.db` (will regenerate with default admin)
2. Clear `db/pact_history.trig` graph data
3. Restart the server

### Test the AI Auditor

Make sure AI is responding before the demo:

```bash
curl -X POST http://localhost:8002/v1/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "What systems are being monitored?"}'
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Re-login, token expired |
| AI not responding | Check `ollama serve` is running |
| No data in tables | Ingest demo events (see setup.md) |
| CORS errors | Check browser console, set `CORS_ALLOW_ORIGINS=*` |
| Slow AI responses | First query loads model; subsequent queries faster |

---

## Backup Plans

### If Ollama Fails
- Skip AI Auditor section
- Say: "The AI component requires a local model—I'll show you that separately"
- Move on to thesis and close

### If Dashboard Breaks
- Switch to curl commands (see script.md backup section)
- Show API responses in terminal
- Say: "Let me show you the raw API—this is what the dashboard calls"

### If Nothing Works
- Use slides only
- Walk through the ecosystem diagram
- Say: "I'll follow up with a recorded demo"

---

## Audience Reminders

| Audience | What They Care About | Key Moment |
|----------|---------------------|------------|
| **Engineers** | API, automation, how it works | Live event simulation |
| **Compliance PMs** | Framework coverage, audit prep | Cross-walk mapping |
| **Directors/VPs** | Risk visibility, ROI | Thesis question |

---

## After the Demo

1. Share the [one-pager.md](one-pager.md) 
2. Offer to do a deeper dive with interested folks
3. If they ask "what would it take to build this for real?" — see script.md closing section

---

*Demo package last updated: January 2026*

