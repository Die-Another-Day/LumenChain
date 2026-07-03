"""
LUMENCHAIN — AI Detection Engine

Hybrid design, deliberately — this is the actually-defensible approach
used in real SOC tooling, not a single silver-bullet model:

  1. SIGNATURE / RULE LAYER — deterministic, explainable detections for
     known attacker techniques (mapped to MITRE ATT&CK where relevant).
     Fast, zero false-negatives for known patterns, fully auditable.

  2. ANOMALY LAYER — scikit-learn IsolationForest over behavioral
     features (event rate, off-hours activity, file-modification burst
     size, entropy of source diversity). Catches things with no
     matching signature — the "unknown unknowns." IsolationForest is
     the right tool here: it's built for exactly this (low-dimensional,
     unlabeled, few-anomalies-among-many-normal-points) and needs no
     labeled attack data to train, which real SOC logs never have
     enough of.

  3. NARRATIVE LAYER — turns structured detections into an
     investigator-readable summary. Template-based by default (fully
     deterministic — no hallucinated facts, satisfies "no false data").
     If an ANTHROPIC_API_KEY is present in the environment, it will
     instead call the Claude API to phrase the same structured findings
     more fluently — the model is given ONLY the structured detections
     already computed, never asked to invent facts.
"""

import os
import re
import math
from collections import Counter
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------------------------
# Signature layer
# ---------------------------------------------------------------------------

SIGNATURES = [
    {
        "id": "SIG-001",
        "category": "Initial Access",
        "technique": "T1566 - Phishing",
        "pattern": re.compile(r"phishing|malicious attachment|suspicious sender", re.I),
        "field": "event_description",
        "severity": "medium",
        "confidence": 0.75,
    },
    {
        "id": "SIG-002",
        "category": "Execution",
        "technique": "T1059.001 - PowerShell",
        "pattern": re.compile(r"powershell\.exe.*-executionpolicy\s+bypass", re.I),
        "field": "event_description",
        "severity": "high",
        "confidence": 0.9,
    },
    {
        "id": "SIG-003",
        "category": "Command and Control",
        "technique": "T1071 - Application Layer Protocol",
        "pattern": re.compile(r"outbound connection", re.I),
        "field": "event_description",
        "severity": "medium",
        "confidence": 0.55,
        "extra_check": "suspicious_ip",
    },
    {
        "id": "SIG-004",
        "category": "Credential Access",
        "technique": "T1003 - OS Credential Dumping",
        "pattern": re.compile(r"credential dump|lsass|mimikatz|sam dump", re.I),
        "field": "event_description",
        "severity": "critical",
        "confidence": 0.92,
    },
    {
        "id": "SIG-005",
        "category": "Privilege Escalation",
        "technique": "T1078.002 - Valid Accounts: Domain Accounts",
        "pattern": re.compile(r"administrator login|domain admin", re.I),
        "field": "event_description",
        "severity": "high",
        "confidence": 0.7,
        "extra_check": "unusual_workstation",
    },
    {
        "id": "SIG-006",
        "category": "Impact",
        "technique": "T1486 - Data Encrypted for Impact",
        "pattern": re.compile(r"files? modified|encrypt", re.I),
        "field": "event_description",
        "severity": "critical",
        "confidence": 0.88,
        "extra_check": "mass_modification",
    },
]

# Private/reserved ranges are NOT flagged; anything else routed through
# this check is treated as "unverified external" rather than asserted
# malicious — we don't have a live threat-intel feed wired in, and
# asserting "known bad IP" without one would be exactly the kind of
# false data the brief asked to avoid. Wire a real feed (AbuseIPDB,
# OTX, internal blocklist) into `is_flagged_ip()` for production use.
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "192.168.", "127.")


def is_flagged_ip(ip: str) -> bool:
    if not ip:
        return False
    return not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)


def run_signature_detection(log: dict) -> list:
    """Returns a list of matched signature detections for a single log entry."""
    text = str(log.get("event_description", "")) + " " + str(log.get("raw", ""))
    hits = []
    for sig in SIGNATURES:
        if sig["pattern"].search(text):
            note = None
            if sig.get("extra_check") == "suspicious_ip":
                ip = log.get("dest_ip") or log.get("ip")
                if not is_flagged_ip(ip):
                    continue
                note = f"destination {ip} is external/unverified (no threat-intel match — flagged on network context only)"
            if sig.get("extra_check") == "unusual_workstation":
                if log.get("workstation", "").lower() not in ("", "unknown"):
                    continue
                note = "source workstation not recognized in asset inventory"
            if sig.get("extra_check") == "mass_modification":
                count = log.get("files_modified", 0)
                if count < 50:
                    continue
                note = f"{count} files modified in a single event — well above normal baseline"

            hits.append({
                "signature_id": sig["id"],
                "category": sig["category"],
                "technique": sig["technique"],
                "severity": sig["severity"],
                "confidence": sig["confidence"],
                "note": note,
            })
    return hits


# ---------------------------------------------------------------------------
# Anomaly layer (IsolationForest over behavioral features)
# ---------------------------------------------------------------------------

def _extract_features(logs: list) -> np.ndarray:
    """
    Builds a per-log feature vector:
      [hour_of_day_sin, hour_of_day_cos, is_off_hours, files_modified,
       source_rarity, event_burst_score]
    """
    sources = [l.get("source", "unknown") for l in logs]
    source_counts = Counter(sources)
    total = max(len(logs), 1)

    times = [l["event_time"] for l in logs]
    times_sorted = sorted(times)

    def burst_score(t):
        # how many events within +/- 30s of this one (rough burst proxy)
        return sum(1 for x in times if abs(x - t) <= 30)

    feats = []
    for l in logs:
        dt = datetime.fromtimestamp(l["event_time"])
        hour = dt.hour + dt.minute / 60.0
        sin_h = math.sin(2 * math.pi * hour / 24)
        cos_h = math.cos(2 * math.pi * hour / 24)
        off_hours = 1.0 if (hour < 6 or hour > 21) else 0.0
        files_mod = float(l.get("files_modified", 0))
        rarity = 1.0 - (source_counts[l.get("source", "unknown")] / total)
        burst = float(burst_score(l["event_time"]))
        feats.append([sin_h, cos_h, off_hours, files_mod, rarity, burst])
    return np.array(feats)


def run_anomaly_detection(logs: list, contamination: float = 0.15) -> dict:
    """
    Returns {log_index: anomaly_score} for logs whose behavioral profile
    is unusual relative to the rest of the case's log set. Needs a
    minimum log volume to be meaningful — below that, IsolationForest
    has nothing to contrast against, so it's skipped rather than
    returning noise dressed up as a finding.
    """
    if len(logs) < 8:
        return {}

    X = _extract_features(logs)
    model = IsolationForest(
        n_estimators=200,
        contamination=min(contamination, 0.4),
        random_state=42,
    )
    model.fit(X)
    raw_scores = model.decision_function(X)  # higher = more normal
    preds = model.predict(X)  # -1 = anomaly, 1 = normal

    results = {}
    for i, (score, pred) in enumerate(zip(raw_scores, preds)):
        if pred == -1:
            # normalize decision_function (~[-0.5, 0.5]) to a 0-1 "anomaly strength"
            strength = max(0.0, min(1.0, 0.5 - score))
            results[i] = round(float(strength), 3)
    return results


# ---------------------------------------------------------------------------
# Narrative layer
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_template_narrative(case_name: str, alerts: list) -> str:
    if not alerts:
        return (f"No signature or anomaly-based detections were raised for case '{case_name}' "
                f"based on the logs ingested so far.")

    by_category = {}
    for a in alerts:
        by_category.setdefault(a["category"], []).append(a)

    top_severity = max(alerts, key=lambda a: SEVERITY_ORDER.get(a["severity"], 0))["severity"]

    lines = [
        f"Case '{case_name}': {len(alerts)} detection(s) across {len(by_category)} MITRE ATT&CK "
        f"categor{'y' if len(by_category)==1 else 'ies'}. Highest observed severity: {top_severity.upper()}.",
        "",
    ]
    ordered = sorted(alerts, key=lambda a: a["event_time"])
    for a in ordered:
        ts = datetime.fromtimestamp(a["event_time"]).strftime("%H:%M:%S")
        conf_pct = round(a["confidence"] * 100)
        lines.append(f"- {ts} — [{a['severity'].upper()}] {a['category']} "
                      f"({a.get('technique','')}) — {a['description']} (confidence {conf_pct}%)")
    return "\n".join(lines)


def build_narrative(case_name: str, alerts: list) -> str:
    """Uses Claude for phrasing IF an API key is configured; otherwise deterministic template."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    template = build_template_narrative(case_name, alerts)
    if not api_key or not alerts:
        return template

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        prompt = (
            "You are drafting the narrative summary section of a SOC incident report. "
            "You are given ONLY the structured detections below — do not invent any fact, "
            "system, IP, timestamp, or detail not present in this data. Write 3-5 sentences, "
            "factual and professional, no speculation beyond what's listed.\n\n"
            f"Case: {case_name}\n\nDetections:\n{template}"
        )
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        return text.strip() or template
    except Exception:
        # Any failure (no network, bad key, quota) falls back silently to the
        # deterministic template — the report must never fail to generate.
        return template


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyze_logs(logs: list) -> list:
    """
    Runs both detection layers across a full log set and returns a unified
    list of alert dicts ready for storage. `logs` items must each include
    `id` (DB row id) alongside the parsed fields.
    """
    alerts = []

    for log in logs:
        sig_hits = run_signature_detection(log["raw_log"])
        for hit in sig_hits:
            desc = SIGNATURE_DESCRIPTIONS.get(hit["signature_id"], hit["technique"])
            if hit["note"]:
                desc += f" ({hit['note']})"
            alerts.append({
                "log_id": log["id"],
                "event_time": log["event_time"],
                "category": hit["category"],
                "technique": hit["technique"],
                "severity": hit["severity"],
                "confidence": hit["confidence"],
                "description": desc,
                "detector": f"signature:{hit['signature_id']}",
            })

    anomaly_scores = run_anomaly_detection(logs)
    for idx, strength in anomaly_scores.items():
        log = logs[idx]
        alerts.append({
            "log_id": log["id"],
            "event_time": log["event_time"],
            "category": "Anomalous Behavior",
            "technique": "Behavioral outlier (IsolationForest)",
            "severity": "medium" if strength < 0.7 else "high",
            "confidence": strength,
            "description": (f"Log deviates from the case's established behavioral baseline "
                             f"(timing, source frequency, or volume) — no matching signature, "
                             f"flagged for analyst review."),
            "detector": "ml:isolation_forest",
        })

    return alerts


SIGNATURE_DESCRIPTIONS = {
    "SIG-001": "Phishing indicator detected in log content",
    "SIG-002": "PowerShell executed with execution policy bypass",
    "SIG-003": "Outbound connection to unverified external host",
    "SIG-004": "Credential dumping activity detected",
    "SIG-005": "Administrator/domain-admin login from unrecognized workstation",
    "SIG-006": "Mass file modification consistent with encryption activity",
}
