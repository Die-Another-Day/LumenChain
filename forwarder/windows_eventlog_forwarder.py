"""
LUMENCHAIN — Windows Event Log Forwarder
------------------------------------------
Plays the same role as a Splunk Universal Forwarder: runs on the machine
that HAS the logs, reads new Windows Event Log entries, translates them
into LUMENCHAIN's ingest schema, and ships them over HTTP.

Requires: pywin32, requests
    pip install pywin32 requests

Must be run with permission to read the target event log (Security log
usually requires Administrator / elevated shell).

Usage:
    python windows_eventlog_forwarder.py --config config.json
"""

import argparse
import json
import time
import sys
import os
from pathlib import Path
from datetime import datetime, timezone

import requests

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except ImportError:
    print("ERROR: pywin32 is required. Install with: pip install pywin32")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Checkpoint handling — remembers the last event RecordNumber we forwarded
# per log channel, so restarts don't resend everything or skip a gap.
# ---------------------------------------------------------------------------

def load_checkpoint(path: Path) -> dict:
    if path.exists():
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_checkpoint(path: Path, checkpoint: dict):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(checkpoint, f, indent=2)
    tmp.replace(path)  # atomic on both POSIX and Windows


# ---------------------------------------------------------------------------
# Local retry queue — if LUMENCHAIN is unreachable, batches are appended
# here (one JSON object per line) instead of being dropped, and retried on
# every loop iteration before new events are read. This matters specifically
# because a dropped log is a permanent gap in the hash-chain, not just a
# missed alert.
# ---------------------------------------------------------------------------

def enqueue_failed_batch(queue_path: Path, logs: list):
    with open(queue_path, "a") as f:
        f.write(json.dumps(logs) + "\n")


def drain_retry_queue(queue_path: Path, send_fn):
    if not queue_path.exists():
        return
    remaining = []
    with open(queue_path, "r") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    for line in lines:
        logs = json.loads(line)
        if not send_fn(logs):
            remaining.append(line)
    if remaining:
        with open(queue_path, "w") as f:
            f.write("\n".join(remaining) + "\n")
    else:
        queue_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Windows Event Log reading
# ---------------------------------------------------------------------------

def win32_time_to_unix(win32_time) -> float:
    """pywin32 event TimeGenerated is a PyTime object; convert to unix epoch seconds."""
    return win32_time.timestamp()


def read_new_events(server: str, log_channel: str, last_record_number: int, max_events: int = 500):
    """
    Reads events newer than last_record_number from the given channel.
    Returns (list_of_events_oldest_first, new_last_record_number).

    Classic win32evtlog doesn't support reliable seek-to-record on a live
    log, so we read backwards from the most recent event and stop once we
    reach the last record we've already forwarded (or hit max_events, to
    bound worst-case work on a busy log / first run).
    """
    hand = win32evtlog.OpenEventLog(server, log_channel)
    try:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        collected = []
        highest_seen = last_record_number

        while len(collected) < max_events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            stop = False
            for ev in events:
                if ev.RecordNumber <= last_record_number:
                    stop = True
                    break
                collected.append(ev)
                if ev.RecordNumber > highest_seen:
                    highest_seen = ev.RecordNumber
            if stop:
                break

        collected.reverse()  # oldest first, matches the order they occurred
        return collected, highest_seen
    finally:
        win32evtlog.CloseEventLog(hand)


def event_to_lumenchain_log(ev, log_channel: str, hostname: str) -> dict:
    """Maps a pywin32 event object to LUMENCHAIN's ingest schema."""
    try:
        message = win32evtlogutil.SafeFormatMessage(ev, log_channel)
    except Exception:
        # Some events have no registered message DLL string available;
        # fall back to whatever raw string data is present rather than
        # dropping the event silently.
        message = " ".join(str(s) for s in (ev.StringInserts or [])) or f"Event ID {ev.EventID}"

    return {
        "source": f"Windows Event Log ({log_channel})",
        "event_time": win32_time_to_unix(ev.TimeGenerated),
        "event_description": f"[EventID {ev.EventID & 0xFFFF}] {message.strip()}",
        "workstation": hostname,
    }


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def send_batch(api_url: str, case_id: str, logs: list, timeout: int = 15) -> bool:
    """Returns True on success, False on any failure (caller decides what to do)."""
    if not logs:
        return True
    try:
        resp = requests.post(
            f"{api_url}/api/logs/ingest",
            json={"case_id": case_id, "logs": logs},
            timeout=timeout,
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"  -> forwarded {result['ingested']} log(s), "
                  f"{result['new_alerts']} new alert(s)")
            return True
        else:
            print(f"  !! ingest failed: HTTP {resp.status_code} — {resp.text[:300]}")
            return False
    except requests.RequestException as e:
        print(f"  !! could not reach LUMENCHAIN at {api_url}: {e}")
        return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(config: dict):
    api_url = config["lumenchain_url"].rstrip("/")
    case_id = config["case_id"]
    channels = config.get("channels", ["Security"])
    poll_interval = config.get("poll_interval_seconds", 15)
    batch_size = config.get("batch_size", 100)
    backfill = config.get("backfill_on_first_run", False)
    server = config.get("event_server", "localhost")  # localhost = this machine

    hostname = os.environ.get("COMPUTERNAME", server)
    checkpoint_path = Path(config.get("checkpoint_file", "checkpoint.json"))
    queue_path = Path(config.get("retry_queue_file", "retry_queue.jsonl"))

    checkpoint = load_checkpoint(checkpoint_path)

    print(f"LUMENCHAIN forwarder starting")
    print(f"  target:   {api_url}  (case: {case_id})")
    print(f"  channels: {channels}")
    print(f"  poll:     every {poll_interval}s, batch size {batch_size}")
    print("Press Ctrl+C to stop.\n")

    def send_fn(logs):
        return send_batch(api_url, case_id, logs)

    while True:
        # Retry anything queued from a previous failed send before reading new events
        drain_retry_queue(queue_path, send_fn)

        for channel in channels:
            last_record = checkpoint.get(channel)

            if last_record is None:
                # First run for this channel: establish a baseline instead of
                # flooding LUMENCHAIN with the entire historical log.
                if backfill:
                    last_record = 0
                else:
                    _, latest = read_new_events(server, channel, 0, max_events=1)
                    checkpoint[channel] = latest
                    save_checkpoint(checkpoint_path, checkpoint)
                    print(f"[{channel}] first run — baseline set at record {latest}, "
                          f"will forward new events from here")
                    continue

            try:
                events, new_last = read_new_events(server, channel, last_record)
            except Exception as e:
                print(f"[{channel}] ERROR reading event log: {e}")
                continue

            if not events:
                continue

            print(f"[{channel}] {len(events)} new event(s)")
            logs = [event_to_lumenchain_log(ev, channel, hostname) for ev in events]

            for i in range(0, len(logs), batch_size):
                batch = logs[i:i + batch_size]
                if not send_fn(batch):
                    enqueue_failed_batch(queue_path, batch)
                    print(f"  queued {len(batch)} log(s) for retry (LUMENCHAIN unreachable)")

            checkpoint[channel] = new_last
            save_checkpoint(checkpoint_path, checkpoint)

        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="LUMENCHAIN Windows Event Log Forwarder")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        print("Copy config.example.json to config.json and edit it first.")
        sys.exit(1)

    with open(config_path) as f:
        config = json.load(f)

    try:
        run(config)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
