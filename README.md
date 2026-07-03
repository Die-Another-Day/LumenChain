# LUMENCHAIN
### AI-Assisted SOC Investigation Platform with Hash-Chain Verified Evidence Integrity

*Lumen (light) + chain (the tamper-evident ledger) — shedding light on the chain of custody.*

---

## What this actually is (read this first)

This is a **working, runnable prototype** — not a mockup, not a slide deck description. Every
piece described below is real code you can run right now: log ingestion, a hybrid
signature + ML detection engine, a cryptographic hash-chain ledger, a live dashboard, and
report export to PDF/HTML/JSON/CSV.

Two things worth being precise about, since precision is what makes this credible in front
of judges, an employer, or a real SOC:

1. **"Blockchain" here means a SHA-256 hash-chain**, not a public distributed blockchain
   network. Every ledger entry embeds the hash of the entry before it, so editing any past
   log breaks every hash that follows — that's the actual mechanism that gives you
   tamper-evidence, and it's genuinely how most "blockchain-verified" logging products work
   under the hood. If you want independent third-party timestamping (so integrity can be
   proven even if someone compromises this server entirely), see
   `anchor_to_external_chain()` in `backend/hashchain.py` — it's a clearly-marked stub, left
   unimplemented because that requires a real RPC endpoint / timestamping authority
   credential that only you can provision.

2. **The IP/threat-intel check is honest about what it doesn't know.** There's no live
   threat-intel feed wired in, so the platform flags external IPs as "unverified" rather
   than asserting "known malicious" — asserting that without a real feed behind it would be
   fabricated confidence. Wire a real feed (AbuseIPDB, OTX, your org's blocklist) into
   `is_flagged_ip()` in `backend/ai_detection.py` for production use.

Say both of these plainly if you present this — it's a stronger pitch than overclaiming,
because it shows you understand what you built and where the real remaining engineering is.

---

## Architecture

```
Log Sources (EDR, Firewall, AD, File Server, VPN, ...)
        │
        ▼
POST /api/logs/ingest  ──────────────────────────┐
        │                                        │
        ▼                                        ▼
  Hash-Chain Ledger                     AI Detection Engine
  (SHA-256, chained,                    ┌─────────────────────┐
   SQLite-backed)                       │ Signature layer:     │
        │                               │  6 rules mapped to   │
        ▼                               │  MITRE ATT&CK        │
  Tamper-evidence on                    │ Anomaly layer:       │
  every read (/api/verify)              │  IsolationForest     │
        │                               │  over behavioral     │
        │                               │  features            │
        │                               └─────────┬───────────┘
        │                                          ▼
        │                                     Alerts (DB)
        │                                          │
        └──────────────┬───────────────────────────┘
                        ▼
              Timeline Reconstruction
                        │
                        ▼
         Dashboard (live) ── Report Export (PDF/HTML/JSON/CSV)
```

## Why these specific technologies

- **FastAPI** — async, typed, auto-generates OpenAPI docs at `/docs`, the standard choice
  for a Python API service you intend to actually run in production, not just demo.
- **SQLite → swap to PostgreSQL for production** — zero-config for the hackathon/demo (unzip
  and run, no DB server to install); the schema is plain SQL, so migrating is a connection
  string change, not a rewrite.
- **scikit-learn IsolationForest** for the anomaly layer — the right algorithm for this
  specific problem: unlabeled data (SOC logs are never fully labeled with "this was an
  attack"), few anomalies among many normal points, and no need for a training corpus of
  known attacks. Random Forest/XGBoost-style supervised models would need labeled attack
  data you don't have; IsolationForest doesn't.
- **Rule/signature layer mapped to MITRE ATT&CK** — because pure ML anomaly detection alone
  is not auditable in an incident report; an investigator (or a court) needs to see *which
  known technique* fired and *why*, deterministically. The hybrid design is deliberate, not
  a compromise — this is the same pattern real SOC/SIEM correlation engines use.
- **ReportLab** for PDF — produces real vector PDF (not a wkhtmltopdf-in-a-headless-browser
  screenshot), which is what you want for a document meant to be submitted as evidence.

## Running it

```bash
# macOS / Linux
./run.sh

# Windows
run.bat
```

This creates a virtual environment, installs dependencies, and starts the server at
**http://localhost:8420**. Open that URL — the dashboard is served from there directly.

Click **"Load Demo Scenario"** to seed the platform with a full hospital-ransomware
scenario (see the disclaimer in `sample_data/demo_ransomware_case.json` — it's fictional
demo data used to exercise every part of the pipeline end to end) and watch the full attack
chain — phishing → PowerShell bypass → C2 callout → credential dumping → privilege
escalation → mass encryption — get detected, timestamped, hash-chained, and laid out on the
timeline automatically.

### Optional: AI-phrased narrative summaries

By default, report narratives are built from a deterministic template (no hallucination
risk — every sentence is generated from structured detection data, nothing invented). If you
set an `ANTHROPIC_API_KEY` environment variable before starting the server, the narrative
section of exported reports will instead be phrased fluently by Claude — but it is only ever
given the already-computed structured detections and explicitly instructed not to introduce
any fact not present in that data. If the call fails for any reason (no network, bad key), it
silently falls back to the template — report generation never breaks because of this.

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # optional
./run.sh
```

## API reference

Full interactive docs (auto-generated) are at `http://localhost:8420/docs` once running.
Key endpoints:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/cases` | Create a case |
| POST | `/api/logs/ingest` | Ingest one or more logs into a case (hashes + analyzes them) |
| GET | `/api/timeline/{case_id}` | Chronological alert timeline |
| GET | `/api/verify/{case_id}` | Recompute and verify the entire hash-chain for a case |
| GET | `/api/ledger/{case_id}` | Raw ledger blocks |
| GET | `/api/report/{case_id}?format=pdf\|html\|json\|csv` | Export investigation report |
| POST | `/api/demo/load` | Seed the demo scenario |

## What's genuinely production-shaped vs. what still needs work before deployment

**Solid as-is:** the hash-chain integrity mechanism, the detection pipeline architecture,
the report generation, the API design.

**Needs work before a real org runs this on live traffic:**
- Authentication/authorization (currently none — add before exposing beyond localhost)
- A real log collector/forwarder agent (currently logs arrive via the ingest API; you'd want
  Filebeat/Fluentd/Winlogbeat-style shippers in front of it for a real fleet)
- A live threat-intelligence feed for the IP reputation check
- PostgreSQL instead of SQLite for concurrent multi-analyst use
- External anchoring of the hash-chain (see the stub mentioned above) if you need proof of
  integrity that doesn't depend on trusting this server wasn't compromised

None of that is hidden — it's called out here and in code comments exactly where it needs to
happen, which is the difference between a prototype you can extend confidently and one that
quietly breaks in production.

## Project structure

```
lumenchain/
├── backend/
│   ├── main.py              FastAPI app + routes
│   ├── database.py          SQLite data layer
│   ├── hashchain.py         Hash-chain ledger (the integrity engine)
│   ├── ai_detection.py      Signature + IsolationForest detection engine
│   └── report_generator.py  PDF / HTML / JSON / CSV export
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js                Vanilla JS — no build step needed
├── sample_data/
│   └── demo_ransomware_case.json
├── requirements.txt
├── run.sh / run.bat
└── README.md
```
