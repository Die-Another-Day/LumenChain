"""
LUMENCHAIN — API Server
Run with: uvicorn main:app --reload --port 8420
"""

import time
import uuid
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database import Database
from hashchain import HashChain
from ai_detection import analyze_logs
from report_generator import export_report, gather_case_report_data

app = FastAPI(title="LUMENCHAIN", description="AI-Assisted SOC Investigation Platform with Hash-Chain Verified Evidence Integrity")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
chain = HashChain(db)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CaseCreate(BaseModel):
    name: str
    case_id: Optional[str] = None


class LogEntry(BaseModel):
    source: str
    event_time: Optional[float] = None      # unix timestamp; defaults to now
    event_description: str
    dest_ip: Optional[str] = None
    workstation: Optional[str] = None
    files_modified: Optional[int] = 0
    extra: Optional[dict] = None


class LogIngestRequest(BaseModel):
    case_id: str
    logs: List[LogEntry]


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@app.post("/api/cases")
def create_case(payload: CaseCreate):
    case_id = payload.case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}"
    db.create_case(case_id, payload.name, time.time())
    return db.get_case(case_id)


@app.get("/api/cases")
def list_cases():
    return db.list_cases()


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


# ---------------------------------------------------------------------------
# Log ingestion + detection
# ---------------------------------------------------------------------------

@app.post("/api/logs/ingest")
def ingest_logs(payload: LogIngestRequest):
    case = db.get_case(payload.case_id)
    if not case:
        db.create_case(payload.case_id, payload.case_id, time.time())

    inserted_logs = []
    for entry in payload.logs:
        event_time = entry.event_time or time.time()
        raw_log = entry.model_dump()
        raw_log["event_time"] = event_time

        block = chain.add_entry(payload.case_id, raw_log, metadata={"source": entry.source})

        log_id = db.insert_log(
            case_id=payload.case_id,
            source=entry.source,
            event_time=event_time,
            raw_log=raw_log,
            ingested_at=time.time(),
            block_index=block.index,
        )
        raw_log["id"] = log_id
        raw_log["event_time"] = event_time
        inserted_logs.append({"id": log_id, "event_time": event_time, "raw_log": raw_log})

    # Run detection across the FULL case log set (anomaly detection needs
    # the whole population to establish a baseline, not just the new batch)
    all_logs = db.get_logs(payload.case_id)
    existing_alert_log_ids = {a["log_id"] for a in db.get_alerts(payload.case_id)}

    findings = analyze_logs(all_logs)
    new_alerts = []
    for f in findings:
        if f["log_id"] in existing_alert_log_ids and f["detector"].startswith("signature:"):
            continue  # avoid duplicate signature alerts on re-analysis
        alert_id = db.insert_alert(
            case_id=payload.case_id, log_id=f["log_id"], event_time=f["event_time"],
            category=f["category"], technique=f["technique"], severity=f["severity"],
            confidence=f["confidence"], description=f["description"], detector=f["detector"],
        )
        new_alerts.append({**f, "id": alert_id})

    return {
        "ingested": len(inserted_logs),
        "new_alerts": len(new_alerts),
        "alerts": new_alerts,
    }


@app.get("/api/logs")
def get_logs(case_id: Optional[str] = None):
    return db.get_logs(case_id)


# ---------------------------------------------------------------------------
# Alerts / timeline
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
def get_alerts(case_id: Optional[str] = None):
    return db.get_alerts(case_id)


@app.get("/api/timeline/{case_id}")
def get_timeline(case_id: str):
    alerts = db.get_alerts(case_id)
    return sorted(alerts, key=lambda a: a["event_time"])


# ---------------------------------------------------------------------------
# Blockchain / integrity verification
# ---------------------------------------------------------------------------

@app.get("/api/verify/{case_id}")
def verify_case_integrity(case_id: str):
    return chain.verify_chain(case_id)


@app.get("/api/ledger/{case_id}")
def get_ledger(case_id: str):
    return db.get_all_blocks(case_id)


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------

@app.get("/api/stats")
def get_stats(case_id: Optional[str] = None):
    logs = db.get_logs(case_id)
    alerts = db.get_alerts(case_id)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1
    integrity = chain.verify_chain(case_id) if case_id else {"valid": True, "details": "Select a case."}
    return {
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "integrity": integrity,
    }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.get("/api/report/{case_id}")
def get_report(case_id: str, format: str = "json"):
    if not db.get_case(case_id):
        raise HTTPException(404, "Case not found")
    try:
        content, mime, filename = export_report(db, chain, case_id, format)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return Response(content=content, media_type=mime,
                     headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------------
# Demo data loader
# ---------------------------------------------------------------------------

@app.post("/api/demo/load")
def load_demo_data():
    """Seeds the platform with the sample ransomware-scenario log set for demo purposes."""
    import json as _json
    demo_path = Path(__file__).parent.parent / "sample_data" / "demo_ransomware_case.json"
    with open(demo_path) as f:
        demo = _json.load(f)

    case_id = demo["case_id"]
    db.create_case(case_id, demo["name"], time.time())

    req = LogIngestRequest(case_id=case_id, logs=[LogEntry(**l) for l in demo["logs"]])
    result = ingest_logs(req)
    return {"case_id": case_id, **result}


# ---------------------------------------------------------------------------
# Frontend static hosting
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def serve_index():
    return FileResponse(str(FRONTEND_DIR / "index.html"))
