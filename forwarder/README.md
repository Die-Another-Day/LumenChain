# LUMENCHAIN Forwarder — Windows Event Log

Runs on the Windows machine you want to monitor. Reads new Security/System
event log entries, maps them to LUMENCHAIN's ingest schema, and POSTs them
to `/api/logs/ingest`. Plays the same role as a Splunk Universal Forwarder.

## 1. Install dependencies

Open **PowerShell as Administrator** (reading the Security log requires
elevation):

```powershell
cd forwarder
pip install -r requirements.txt
```

## 2. Enable command-line auditing (important — do this or PowerShell detection is blind)

By default, Windows logs "a process started" (Event ID 4688) but **not**
the actual command line used — so `SIG-002` (PowerShell execution-policy
bypass detection) won't have anything to match against unless this is on.

Run as Administrator:

```powershell
# Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable command-line logging inside those audit events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

(Equivalent Group Policy path if you prefer the GUI:
`Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events`.)

## 3. Configure the forwarder

```powershell
copy config.example.json config.json
notepad config.json
```

Fields you'll actually want to change:

| Field | What it does |
|---|---|
| `lumenchain_url` | Where LUMENCHAIN's API is running (`http://localhost:8420` if same machine) |
| `case_id` | Which case to forward into — must match a case that exists (or use `CASE-DEMO01` / create one first via the dashboard's "+ New Case") |
| `channels` | Which Windows Event Log channels to watch — `Security` is where logons, privilege use, and (with the audit policy above) process creation live |
| `poll_interval_seconds` | How often to check for new events |
| `backfill_on_first_run` | `false` (default) = start from "now," ignoring history. `true` = forward the entire existing log on first run — can be a lot of data, use with care |

## 4. Run it

```powershell
python windows_eventlog_forwarder.py --config config.json
```

You'll see output like:

```
LUMENCHAIN forwarder starting
  target:   http://localhost:8420  (case: CASE-DEMO01)
  channels: ['Security', 'System']
  poll:     every 15s, batch size 100
Press Ctrl+C to stop.

[Security] first run — baseline set at record 481920, will forward new events from here
[Security] 3 new event(s)
  -> forwarded 3 log(s), 1 new alert(s)
```

Leave it running in that terminal (or set it up as a scheduled task — see
below) and go do something that generates events: open PowerShell with
`-ExecutionPolicy Bypass`, log in as a different user, etc. Watch the
LUMENCHAIN dashboard update within one poll interval.

## 5. Running it continuously (optional)

For anything beyond a demo session, don't leave a PowerShell window open —
register it as a **Scheduled Task** set to run at startup:

```powershell
schtasks /create /tn "LumenchainForwarder" /tr "python C:\path\to\forwarder\windows_eventlog_forwarder.py --config C:\path\to\forwarder\config.json" /sc onstart /ru SYSTEM
```

Running as `SYSTEM` ensures it has permission to read the Security log
regardless of which user is logged in.

## What it does and doesn't handle

**Handles:**
- New-events-only reads via a checkpoint file (`checkpoint.json`) — restart-safe, no duplicate or skipped events
- Batches events instead of sending one HTTP request per log
- If LUMENCHAIN is unreachable, failed batches go to `retry_queue.jsonl` and are retried every loop instead of being dropped — a dropped log is a permanent gap in the hash-chain, not just a missed alert, so this matters more here than in typical log shipping

**Doesn't handle (by design, out of scope for this file):**
- Firewall / network logs — those come from your firewall's syslog export, not Windows Event Log. That needs a separate syslog-listener forwarder (different source, different transport — say if you want this one built next).
- File-server mass-modification events (`SIG-006` in the detection engine) — that needs File System Access auditing on the specific share, which is a different event source and setup than what's covered here.
- Multiple machines — this forwards from the machine it runs on. For a fleet, you'd run one instance per machine, each pointed at the same `case_id` (or different cases, depending on how you want to scope investigations).
