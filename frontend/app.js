const API = "";
let currentCase = null;

const $ = (sel) => document.querySelector(sel);

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function refreshCases() {
  const cases = await api("/api/cases");
  const sel = $("#caseSelect");
  sel.innerHTML = "";
  if (cases.length === 0) {
    sel.innerHTML = `<option value="">No cases yet</option>`;
    return;
  }
  cases.forEach((c) => {
    const opt = document.createElement("option");
    opt.value = c.case_id;
    opt.textContent = `${c.name} (${c.case_id})`;
    sel.appendChild(opt);
  });
  currentCase = currentCase && cases.find(c => c.case_id === currentCase) ? currentCase : cases[0].case_id;
  sel.value = currentCase;
  await refreshAll();
}

async function refreshAll() {
  if (!currentCase) return;
  const [stats, timeline, ledger] = await Promise.all([
    api(`/api/stats?case_id=${currentCase}`),
    api(`/api/timeline/${currentCase}`),
    api(`/api/ledger/${currentCase}`),
  ]);
  renderStats(stats);
  renderTimeline(timeline);
  renderLedger(ledger);
}

function renderStats(stats) {
  $("#statLogs").textContent = stats.total_logs;
  $("#statAlerts").textContent = stats.total_alerts;
  $("#statCritical").textContent = stats.severity_counts.critical || 0;
  $("#statHigh").textContent = stats.severity_counts.high || 0;
  $("#statMedium").textContent = stats.severity_counts.medium || 0;

  const badge = $("#integrityBadge");
  if (stats.integrity.valid) {
    badge.className = "badge badge-good";
    badge.textContent = "✓ Chain Verified — No Tampering Detected";
  } else {
    badge.className = "badge badge-bad";
    badge.textContent = "⚠ Integrity Breach Detected — block " + stats.integrity.first_break_index;
  }
}

function renderTimeline(timeline) {
  const el = $("#timeline");
  if (timeline.length === 0) {
    el.innerHTML = `<div class="empty">No detections yet. Ingest logs to populate the timeline.</div>`;
    return;
  }
  el.innerHTML = timeline.map(a => {
    const t = new Date(a.event_time * 1000).toLocaleTimeString();
    return `<div class="tl-item sev-${a.severity}">
      <div class="tl-time">${t}</div>
      <div class="tl-sev sev-${a.severity}">${a.severity}</div>
      <div class="tl-desc">${a.description}<span class="tl-cat">${a.category} — ${a.technique || ""}</span></div>
    </div>`;
  }).join("");
}

function renderLedger(blocks) {
  const el = $("#ledger");
  if (blocks.length === 0) {
    el.innerHTML = `<div class="empty">No ledger blocks yet.</div>`;
    return;
  }
  el.innerHTML = blocks.slice().reverse().map(b => `
    <div class="block">
      <span class="idx">#${b.index}</span> block_hash:<br>
      <span class="hash">${b.block_hash}</span>
    </div>`).join("");
}

async function ingestManualLog() {
  const raw = $("#logInput").value.trim();
  if (!raw) return;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    alert("Invalid JSON. Example: " + $("#logInput").placeholder);
    return;
  }
  if (!currentCase) {
    await api("/api/cases", { method: "POST", body: JSON.stringify({ name: "Untitled Case" }) });
    await refreshCases();
  }
  await api("/api/logs/ingest", {
    method: "POST",
    body: JSON.stringify({ case_id: currentCase, logs: [parsed] }),
  });
  $("#logInput").value = "";
  await refreshAll();
}

async function createNewCase() {
  const name = prompt("Case name:", "New Investigation");
  if (!name) return;
  const c = await api("/api/cases", { method: "POST", body: JSON.stringify({ name }) });
  currentCase = c.case_id;
  await refreshCases();
}

async function loadDemo() {
  await api("/api/demo/load", { method: "POST" });
  await refreshCases();
}

function exportReport(fmt) {
  if (!currentCase) { alert("Select a case first."); return; }
  window.open(`/api/report/${currentCase}?format=${fmt}`, "_blank");
}

$("#caseSelect").addEventListener("change", (e) => { currentCase = e.target.value; refreshAll(); });
$("#newCaseBtn").addEventListener("click", createNewCase);
$("#loadDemoBtn").addEventListener("click", loadDemo);
$("#ingestBtn").addEventListener("click", ingestManualLog);
document.querySelectorAll(".btn-export").forEach(b => b.addEventListener("click", () => exportReport(b.dataset.fmt)));

refreshCases();
setInterval(refreshAll, 8000);
