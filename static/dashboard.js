const GAUGE_CIRCUMFERENCE = 251;

function setGauge(level) {
  // level: 0 (calm) - 1 (critical)
  const fill = document.getElementById('gauge-fill');
  const readout = document.getElementById('gauge-readout');
  const offset = GAUGE_CIRCUMFERENCE * (1 - level);
  fill.style.strokeDashoffset = offset;

  let color, label;
  if (level < 0.15) { color = '#39d67a'; label = 'NOMINAL'; }
  else if (level < 0.5) { color = '#f5a623'; label = 'ELEVATED'; }
  else { color = '#ff5f56'; label = 'CRITICAL'; }

  fill.style.stroke = color;
  readout.style.color = color;
  readout.textContent = label;
}

function fmtNum(n, digits = 1) {
  if (n === undefined || n === null) return '—';
  return Number(n).toFixed(digits);
}

async function poll() {
  try {
    const [statusRes, flowsRes, alertsRes] = await Promise.all([
      fetch('/api/status').then(r => r.json()),
      fetch('/api/flows').then(r => r.json()),
      fetch('/api/alerts').then(r => r.json()),
    ]);

    document.getElementById('stat-hosts').textContent = statusRes.tracked_hosts;
    document.getElementById('stat-alerts').textContent = statusRes.total_alerts;
    document.getElementById('stat-model').textContent = statusRes.model_fitted ? 'active' : 'warming up';
    document.getElementById('stat-uptime').textContent = statusRes.uptime_seconds + 's';

    const recentAlertRate = alertsRes.filter(a => (Date.now() / 1000 - a.ts) < 20).length;
    const level = Math.min(1, recentAlertRate / 6);
    setGauge(level);

    renderFlows(flowsRes, alertsRes);
    renderAlerts(alertsRes);
  } catch (e) {
    console.error('poll failed', e);
  }
}

function renderFlows(flows, alerts) {
  const flaggedIPs = new Set(alerts.slice(0, 20).map(a => a.src_ip));
  const body = document.getElementById('flows-body');

  if (!flows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">Waiting for traffic…</td></tr>';
    return;
  }

  body.innerHTML = flows.map(row => {
    const f = row.features;
    const flagged = flaggedIPs.has(row.src_ip);
    return `<tr class="${flagged ? 'flagged' : ''}">
      <td>${row.src_ip}</td>
      <td>${fmtNum(f.pkt_rate)}</td>
      <td>${fmtNum(f.byte_rate, 0)}</td>
      <td>${f.unique_dst_ips}</td>
      <td>${f.unique_dst_ports}</td>
      <td>${fmtNum(f.syn_ratio, 2)}</td>
    </tr>`;
  }).join('');
}

function renderAlerts(alerts) {
  const feed = document.getElementById('alert-feed');
  if (!alerts.length) {
    feed.innerHTML = '<div class="empty">No anomalies detected yet.</div>';
    return;
  }

  feed.innerHTML = alerts.slice(0, 30).map(a => {
    const time = new Date(a.ts * 1000).toLocaleTimeString();
    const rules = a.rule_hits.length ? a.rule_hits.join(', ') : 'ML outlier';
    const mitre = a.mitre.length ? `<div class="mitre">${a.mitre.join(' · ')}</div>` : '';
    return `<div class="alert-item">
      <div class="alert-head"><span>${a.src_ip}</span><span>${time}</span></div>
      <div class="alert-detail">${rules}</div>
      ${mitre}
    </div>`;
  }).join('');
}

function tickClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}

setInterval(poll, 2000);
setInterval(tickClock, 1000);
poll();
tickClock();
