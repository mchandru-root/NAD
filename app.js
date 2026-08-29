/* ============================================================
   NETWATCH — client-side network anomaly detector
   All parsing + detection happens in the browser. No data is
   sent anywhere. See python/anomaly_detector.py for the offline
   ML-based (IsolationForest) counterpart.
   ============================================================ */

const SENSITIVE_PORTS = new Set([23, 3389, 445, 21, 3306]);
const PORT_SCAN_THRESHOLD = 15;   // distinct dst ports from one src
const RST_RATIO_THRESHOLD = 0.5;  // failed-connection ratio
const BEACON_MIN_HITS = 6;        // repeated hits to same dst
const BEACON_JITTER_TOLERANCE = 0.25; // 25% variance allowed in interval

let state = { flows: [], hostFindings: [] };

// ---------- CSV parsing ----------
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  const headers = lines[0].split(",").map(h => h.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i]) continue;
    const cells = lines[i].split(",");
    const row = {};
    headers.forEach((h, idx) => (row[h] = cells[idx] !== undefined ? cells[idx].trim() : ""));
    row.timestamp = new Date(row.timestamp);
    row.src_port = Number(row.src_port);
    row.dst_port = Number(row.dst_port);
    row.bytes = Number(row.bytes);
    row.packets = Number(row.packets);
    row.duration_ms = Number(row.duration_ms);
    rows.push(row);
  }
  return rows;
}

// ---------- Detection ----------
function analyze(flows) {
  flows.sort((a, b) => a.timestamp - b.timestamp);
  const bySrc = new Map();
  for (const f of flows) {
    if (!bySrc.has(f.src_ip)) bySrc.set(f.src_ip, []);
    bySrc.get(f.src_ip).push(f);
  }

  // Global baseline for volume z-score
  const totalBytesPerHost = [...bySrc.values()].map(fs => fs.reduce((s, f) => s + f.bytes, 0));
  const mean = totalBytesPerHost.reduce((a, b) => a + b, 0) / totalBytesPerHost.length;
  const variance = totalBytesPerHost.reduce((a, b) => a + (b - mean) ** 2, 0) / totalBytesPerHost.length;
  const std = Math.sqrt(variance) || 1;

  const findings = [];

  for (const [src, fs] of bySrc.entries()) {
    const distinctPorts = new Set(fs.map(f => f.dst_port));
    const distinctDstIps = new Set(fs.map(f => f.dst_ip));
    const totalBytes = fs.reduce((s, f) => s + f.bytes, 0);
    const rstCount = fs.filter(f => f.flag === "RST").length;
    const rstRatio = rstCount / fs.length;
    const sensitiveHits = fs.filter(f => SENSITIVE_PORTS.has(f.dst_port)).length;
    const zScore = (totalBytes - mean) / std;

    const detections = [];

    if (distinctPorts.size >= PORT_SCAN_THRESHOLD) {
      detections.push({ type: "Port Scan", severity: "Critical",
        detail: `Touched ${distinctPorts.size} distinct destination ports across ${fs.length} flows.` });
    }
    if (sensitiveHits > 0) {
      const ports = [...new Set(fs.filter(f => SENSITIVE_PORTS.has(f.dst_port)).map(f => f.dst_port))];
      detections.push({ type: "Sensitive Port Access", severity: "High",
        detail: `Accessed sensitive port(s) ${ports.join(", ")} — ${sensitiveHits} flow(s).` });
    }
    if (rstRatio > RST_RATIO_THRESHOLD && fs.length >= 5) {
      detections.push({ type: "High Failed-Connection Ratio", severity: "High",
        detail: `${(rstRatio * 100).toFixed(0)}% of ${fs.length} flows reset (RST) — possible brute-force or scan.` });
    }
    if (zScore > 3) {
      detections.push({ type: "Volume Anomaly", severity: zScore > 6 ? "Critical" : "Medium",
        detail: `Transferred ${formatBytes(totalBytes)} — z-score ${zScore.toFixed(1)} vs capture baseline.` });
    }

    // Beaconing: group by dst, check regular intervals
    const byDst = new Map();
    for (const f of fs) {
      if (!byDst.has(f.dst_ip)) byDst.set(f.dst_ip, []);
      byDst.get(f.dst_ip).push(f.timestamp.getTime());
    }
    for (const [dst, times] of byDst.entries()) {
      if (times.length < BEACON_MIN_HITS) continue;
      times.sort((a, b) => a - b);
      const intervals = [];
      for (let i = 1; i < times.length; i++) intervals.push(times[i] - times[i - 1]);
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const maxDeviation = Math.max(...intervals.map(iv => Math.abs(iv - avgInterval) / avgInterval));
      if (maxDeviation < BEACON_JITTER_TOLERANCE) {
        detections.push({ type: "Possible Beaconing", severity: "Medium",
          detail: `${times.length} calls to ${dst} at ~${Math.round(avgInterval / 1000)}s intervals (low jitter).` });
      }
    }

    if (detections.length > 0) {
      const severityRank = { Critical: 3, High: 2, Medium: 1 };
      const topSeverity = detections.reduce((top, d) =>
        severityRank[d.severity] > severityRank[top] ? d.severity : top, "Medium");
      const score = detections.reduce((s, d) => s + severityRank[d.severity], 0);
      findings.push({
        src, flowCount: fs.length, distinctPorts: distinctPorts.size,
        distinctDstIps: distinctDstIps.size, totalBytes, severity: topSeverity,
        score, detections, firstSeen: fs[0].timestamp, lastSeen: fs[fs.length - 1].timestamp,
      });
    }
  }

  findings.sort((a, b) => b.score - a.score);
  return findings;
}

function formatBytes(n) {
  if (n > 1_000_000) return (n / 1_000_000).toFixed(1) + " MB";
  if (n > 1_000) return (n / 1_000).toFixed(1) + " KB";
  return n + " B";
}

// ---------- Rendering ----------
function renderStats(flows, findings) {
  const hosts = new Set(flows.map(f => f.src_ip)).size;
  const critical = findings.filter(f => f.severity === "Critical").length;
  const first = flows[0]?.timestamp, last = flows[flows.length - 1]?.timestamp;
  const windowMin = first && last ? Math.max(1, Math.round((last - first) / 60000)) : 0;

  document.getElementById("statFlows").textContent = flows.length.toLocaleString();
  document.getElementById("statHosts").textContent = hosts;
  document.getElementById("statAnomalies").textContent = findings.length;
  document.getElementById("statCritical").textContent = critical;
  document.getElementById("statWindow").textContent = windowMin + " min";

  const dot = document.getElementById("statusDot");
  dot.classList.toggle("alert", critical > 0);
}

function renderTable(findings) {
  const tbody = document.getElementById("anomalyTableBody");
  if (findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="table-empty">No anomalies found in this capture.</td></tr>`;
    return;
  }
  tbody.innerHTML = "";
  findings.forEach((f, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td>${f.src}</td>
      <td>${f.detections.map(d => d.type).join(", ")}</td>
      <td>${f.flowCount}</td>
      <td>${f.distinctPorts}</td>
      <td>${formatBytes(f.totalBytes)}</td>
      <td>${f.score}</td>
    `;
    tr.addEventListener("click", () => showDetail(f));
    tbody.appendChild(tr);
  });
}

function showDetail(f) {
  const panel = document.getElementById("detailPanel");
  document.getElementById("detailTitle").textContent = `Host detail — ${f.src}`;
  document.getElementById("detailBody").innerHTML = `
    <div class="detail-row"><span>Severity</span><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></div>
    <div class="detail-row"><span>Flows</span><span>${f.flowCount}</span></div>
    <div class="detail-row"><span>Distinct destination ports</span><span>${f.distinctPorts}</span></div>
    <div class="detail-row"><span>Distinct destination hosts</span><span>${f.distinctDstIps}</span></div>
    <div class="detail-row"><span>Total bytes</span><span>${formatBytes(f.totalBytes)}</span></div>
    <div class="detail-row"><span>First seen</span><span>${f.firstSeen.toLocaleString()}</span></div>
    <div class="detail-row"><span>Last seen</span><span>${f.lastSeen.toLocaleString()}</span></div>
    <div class="detail-findings">
      ${f.detections.map(d => `<span class="badge badge-${d.severity.toLowerCase()}" title="${d.detail}">${d.type}</span>`).join("")}
    </div>
    <div style="margin-top:14px; color: var(--text-muted); font-size: 12.5px;">
      ${f.detections.map(d => `<div style="margin-bottom:6px;">▸ ${d.detail}</div>`).join("")}
    </div>
  `;
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "center" });
}

document.getElementById("closeDetail").addEventListener("click", () => {
  document.getElementById("detailPanel").hidden = true;
});

// ---------- Live console stream ----------
function streamConsole(findings) {
  const consoleEl = document.getElementById("eventConsole");
  const note = document.getElementById("consoleNote");
  consoleEl.innerHTML = "";
  if (findings.length === 0) {
    consoleEl.innerHTML = `<div class="console-empty">No detections — traffic looks clean.</div>`;
    note.textContent = "0 events";
    return;
  }
  note.textContent = `streaming ${findings.length} events`;

  // Flatten all detections into a single timeline, most severe first per host
  const events = [];
  findings.forEach(f => f.detections.forEach(d => events.push({ src: f.src, ...d })));

  let i = 0;
  function pushNext() {
    if (i >= events.length) return;
    const e = events[i++];
    const line = document.createElement("div");
    line.className = `console-line sev-${e.severity.toLowerCase()}`;
    const time = new Date().toLocaleTimeString();
    line.innerHTML = `<span class="ts">${time}</span><span class="sev">${e.severity.toUpperCase()}</span><span class="msg"><strong>${e.type}</strong> — ${e.src} · ${e.detail}</span>`;
    consoleEl.prepend(line);
    while (consoleEl.children.length > 60) consoleEl.removeChild(consoleEl.lastChild);
    setTimeout(pushNext, 90);
  }
  pushNext();
}

// ---------- Chart (lightweight canvas, no dependency) ----------
function renderChart(flows, findings) {
  const canvas = document.getElementById("volumeChart");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const cssWidth = canvas.parentElement.clientWidth - 44;
  canvas.width = cssWidth * dpr;
  canvas.height = 220 * dpr;
  canvas.style.width = cssWidth + "px";
  canvas.style.height = "220px";
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, cssWidth, 220);

  if (flows.length === 0) return;

  // bucket by minute
  const first = flows[0].timestamp.getTime();
  const buckets = new Map();
  const flaggedHosts = new Set(findings.map(f => f.src));
  for (const f of flows) {
    const bucket = Math.floor((f.timestamp.getTime() - first) / 60000);
    if (!buckets.has(bucket)) buckets.set(bucket, { total: 0, flagged: 0 });
    const b = buckets.get(bucket);
    b.total += f.bytes;
    if (flaggedHosts.has(f.src_ip)) b.flagged += f.bytes;
  }
  const maxBucket = Math.max(...buckets.keys());
  const maxVal = Math.max(...[...buckets.values()].map(b => b.total), 1);

  const padL = 46, padB = 24, padT = 10;
  const chartW = cssWidth - padL - 10;
  const chartH = 220 - padB - padT;
  const barW = chartW / (maxBucket + 1);

  // gridlines
  ctx.strokeStyle = "rgba(255,255,255,0.06)";
  ctx.fillStyle = "#5B6A8A";
  ctx.font = "10px JetBrains Mono, monospace";
  ctx.textAlign = "right";
  for (let g = 0; g <= 4; g++) {
    const y = padT + chartH - (chartH * g) / 4;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(cssWidth - 6, y);
    ctx.stroke();
    ctx.fillText(formatBytes(Math.round((maxVal * g) / 4)), padL - 8, y + 3);
  }

  for (let b = 0; b <= maxBucket; b++) {
    const data = buckets.get(b) || { total: 0, flagged: 0 };
    const x = padL + b * barW;
    const hTotal = (data.total / maxVal) * chartH;
    const hFlagged = (data.flagged / maxVal) * chartH;
    ctx.fillStyle = "rgba(79, 209, 197, 0.35)";
    ctx.fillRect(x + 1, padT + chartH - hTotal, Math.max(barW - 2, 1), hTotal);
    if (data.flagged > 0) {
      ctx.fillStyle = "#FF6B4A";
      ctx.fillRect(x + 1, padT + chartH - hFlagged, Math.max(barW - 2, 1), hFlagged);
    }
  }

  ctx.fillStyle = "#8592AD";
  ctx.textAlign = "left";
  ctx.fillText("teal = baseline traffic · orange = flagged-host traffic", padL, 14);
}

// ---------- Load pipeline ----------
function loadData(text, label) {
  const flows = parseCSV(text);
  if (flows.length === 0) {
    document.getElementById("fileHint").textContent = "Couldn't parse that file — check the CSV format in README.md.";
    return;
  }
  const findings = analyze(flows);
  state = { flows, hostFindings: findings };

  document.getElementById("fileHint").textContent = `Loaded ${label} — ${flows.length.toLocaleString()} flows.`;
  renderStats(flows, findings);
  renderTable(findings);
  renderChart(flows, findings);
  streamConsole(findings);
  document.getElementById("detailPanel").hidden = true;
}

document.getElementById("fileInput").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (evt) => loadData(evt.target.result, file.name);
  reader.readAsText(file);
});

document.getElementById("loadSampleBtn").addEventListener("click", async () => {
  document.getElementById("fileHint").textContent = "Loading sample capture...";
  try {
    const res = await fetch("sample-data/network_traffic_sample.csv");
    const text = await res.text();
    loadData(text, "sample capture");
  } catch (err) {
    document.getElementById("fileHint").textContent =
      "Couldn't fetch sample data (if you opened this file directly, run a local server — see README.md).";
  }
});

window.addEventListener("resize", () => {
  if (state.flows.length) renderChart(state.flows, state.hostFindings);
});
