/* NIDS Dashboard — user-friendly real-time monitoring */

const API = "/api/v1";
const POLL_MS = 2000;

// ── Auth ──
const TOKEN_KEY = "nids_token";
const nsToken = localStorage.getItem(TOKEN_KEY);
const nsRole = localStorage.getItem("nids_role") || "viewer";
const nsUsername = localStorage.getItem("nids_username") || "";
const nsName = localStorage.getItem("nids_name") || nsUsername;

if (!nsToken) {
  window.location.href = "/login";
}

function authHeaders() {
  return nsToken ? { "Authorization": "Bearer " + nsToken } : {};
}

// Display user info
document.getElementById("user-display-name").textContent = nsUsername;
const roleBadge = document.getElementById("user-role-badge");
roleBadge.textContent = nsRole.toUpperCase();
roleBadge.classList.add("role-" + nsRole);

// Logout
document.getElementById("logout-btn").addEventListener("click", function () {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem("nids_role");
  localStorage.removeItem("nids_name");
  localStorage.removeItem("nids_username");
  window.location.href = "/login";
});

// Role-based UI restrictions
if (nsRole === "viewer") {
  var simCard = document.querySelector(".simulate-card");
  if (simCard) simCard.style.display = "none";
  var captureRight = document.querySelector(".capture-right");
  if (captureRight) captureRight.style.display = "none";
}

// ── Real CIC-IDS2017 flow presets (high-confidence samples) ──
const PRESETS = {
  benign: {
    flow_duration: 46367, total_fwd_packets: 1, total_bwd_packets: 1,
    fwd_packet_length_mean: 48, bwd_packet_length_mean: 233,
    flow_bytes_per_sec: 6060.34, flow_packets_per_sec: 43.13,
    packet_length_mean: 109.67, packet_length_std: 106.81, packet_length_variance: 11408.33,
    avg_packet_size: 164.5, fwd_segment_size_avg: 48, bwd_segment_size_avg: 233,
    subflow_fwd_packets: 1, subflow_bwd_packets: 1,
    init_win_bytes_fwd: -1, init_win_bytes_bwd: -1, fwd_header_length: 20,
  },
  ddos: {
    flow_duration: 844124, total_fwd_packets: 3, total_bwd_packets: 5,
    fwd_packet_length_mean: 8.67, bwd_packet_length_mean: 2321.4,
    flow_bytes_per_sec: 13781.15, flow_packets_per_sec: 9.48,
    fwd_iat_mean: 501, bwd_iat_mean: 211019, fwd_iat_std: 683.07,
    packet_length_mean: 1292.56, packet_length_std: 3350.63, packet_length_variance: 11200000,
    psh_flag_count: 1, avg_packet_size: 1454.12, fwd_segment_size_avg: 8.67,
    bwd_segment_size_avg: 2321.4, subflow_fwd_packets: 3, subflow_bwd_packets: 5,
    init_win_bytes_fwd: 8192, init_win_bytes_bwd: 229, fwd_header_length: 72,
  },
  portscan: {
    flow_duration: 2673.52, total_fwd_packets: 4.88, total_bwd_packets: 1.11,
    fwd_packet_length_mean: 28.31, bwd_packet_length_mean: 36.62,
    flow_bytes_per_sec: 15328.47, flow_packets_per_sec: 39930.79,
    fwd_iat_mean: 760.67, bwd_iat_mean: 2037.65, fwd_iat_std: 509.23,
    packet_length_mean: 29.85, packet_length_std: 9.96, packet_length_variance: 99.27,
    fin_flag_count: 0.73, syn_flag_count: 2.43, rst_flag_count: 1.98,
    psh_flag_count: 0.69, ack_flag_count: 1.52, down_up_ratio: 0.41,
    avg_packet_size: 30.89, fwd_segment_size_avg: 28.31, bwd_segment_size_avg: 36.62,
    subflow_fwd_packets: 4.88, subflow_bwd_packets: 1.11,
    init_win_bytes_fwd: 799.59, init_win_bytes_bwd: 126.88,
    active_mean: 842.65, idle_mean: 21.42, fwd_header_length: 97.53,
  },
  bruteforce: {
    flow_duration: 9607531, total_fwd_packets: 9, total_bwd_packets: 15,
    fwd_packet_length_mean: 11, bwd_packet_length_mean: 12.53,
    flow_bytes_per_sec: 29.87, flow_packets_per_sec: 2.5,
    fwd_iat_mean: 793244, bwd_iat_mean: 686240.43, fwd_iat_std: 1467432.53,
    packet_length_mean: 11.48, packet_length_std: 12.41, packet_length_variance: 154.09,
    psh_flag_count: 1, avg_packet_size: 11.96, fwd_segment_size_avg: 11,
    bwd_segment_size_avg: 12.53, subflow_fwd_packets: 9, subflow_bwd_packets: 15,
    init_win_bytes_fwd: 29200, init_win_bytes_bwd: 227, fwd_header_length: 296,
  },
  botnet: {
    flow_duration: 2086137.43, total_fwd_packets: 25.49, total_bwd_packets: 20.2,
    fwd_packet_length_mean: 107.19, bwd_packet_length_mean: 196.75,
    flow_bytes_per_sec: 5033.33, flow_packets_per_sec: 8.85,
    fwd_iat_mean: 42917.27, bwd_iat_mean: 132607.56, fwd_iat_std: 6180.17,
    packet_length_mean: 146.79, packet_length_std: 68.39, packet_length_variance: 4676.66,
    fin_flag_count: 1.12, syn_flag_count: 1.52, rst_flag_count: 0.04,
    psh_flag_count: 4.38, ack_flag_count: 26.24, down_up_ratio: 2.45,
    avg_packet_size: 229.65, fwd_segment_size_avg: 107.19, bwd_segment_size_avg: 196.75,
    subflow_fwd_packets: 25.49, subflow_bwd_packets: 20.2,
    init_win_bytes_fwd: 14914.86, init_win_bytes_bwd: 16515.3,
    active_mean: 394884.28, idle_mean: 519871.12, fwd_header_length: 509.73,
  },
  infiltration: {
    flow_duration: 8447295.56, total_fwd_packets: 140.45, total_bwd_packets: 118.44,
    fwd_packet_length_mean: 601.83, bwd_packet_length_mean: 1360.54,
    flow_bytes_per_sec: 68585.89, flow_packets_per_sec: 59.81,
    fwd_iat_mean: 64192.09, bwd_iat_mean: 97931.1, fwd_iat_std: 42314.12,
    packet_length_mean: 948.93, packet_length_std: 412.33, packet_length_variance: 170014.33,
    fin_flag_count: 0.03, syn_flag_count: 1.4, rst_flag_count: 1.57,
    psh_flag_count: 39.48, ack_flag_count: 43.6, urg_flag_count: 0.49,
    down_up_ratio: 1.64, avg_packet_size: 749.84, fwd_segment_size_avg: 601.83,
    bwd_segment_size_avg: 1360.54, subflow_fwd_packets: 140.45, subflow_bwd_packets: 118.44,
    init_win_bytes_fwd: 35989.55, init_win_bytes_bwd: 18905.31,
    active_mean: 2911385.06, idle_mean: 1906128.27, fwd_header_length: 2808.98,
  },
  webattack: {
    flow_duration: 238960.64, total_fwd_packets: 44.03, total_bwd_packets: 46.97,
    fwd_packet_length_mean: 331.97, bwd_packet_length_mean: 1566.51,
    flow_bytes_per_sec: 122184.39, flow_packets_per_sec: 111.78,
    fwd_iat_mean: 4479.26, bwd_iat_mean: 3874.36, fwd_iat_std: 969.94,
    packet_length_mean: 969.2, packet_length_std: 211.35, packet_length_variance: 44667.04,
    fin_flag_count: 1.89, syn_flag_count: 1.87, rst_flag_count: 0.18,
    psh_flag_count: 17.6, ack_flag_count: 23.21, urg_flag_count: 0.24,
    down_up_ratio: 2.85, avg_packet_size: 1222.09, fwd_segment_size_avg: 331.97,
    bwd_segment_size_avg: 1566.51, subflow_fwd_packets: 44.03, subflow_bwd_packets: 46.97,
    init_win_bytes_fwd: 38711.3, init_win_bytes_bwd: 17186.03,
    active_mean: 106294.52, idle_mean: 24642.46, fwd_header_length: 880.52,
  },
};

// ── Helpers ──
function jitter(flow) {
  const out = {};
  for (const k in flow) {
    const v = flow[k];
    out[k] = Math.max(0, v * (1 + (Math.random() - 0.5) * 0.16));
  }
  return out;
}
function fmt(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(n);
}
function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString("en-GB", { hour12: false });
}

function handleAuthError(r) {
  if (r.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem("nids_role");
    localStorage.removeItem("nids_name");
    localStorage.removeItem("nids_username");
    window.location.href = "/login";
    throw new Error("Session expired");
  }
}

async function apiGet(path) {
  const r = await fetch(API + path, { headers: authHeaders() });
  handleAuthError(r);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
async function apiPost(path, body) {
  const headers = Object.assign({ "Content-Type": "application/json" }, authHeaders());
  const r = await fetch(API + path, {
    method: "POST", headers: headers,
    body: JSON.stringify(body),
  });
  handleAuthError(r);
  if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
  return r.json();
}
async function apiDelete(path) {
  const r = await fetch(API + path, { method: "DELETE", headers: authHeaders() });
  handleAuthError(r);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// ── River animation state (declared early — referenced by renderPipeline & simulate) ──
const river = {
  particles: [],
  newSafe: 0,
  newAttack: 0,
  newRaw: 0,
  total: 0,
  attacks: 0,
  blocked: 0,
};

// ── Clock ──
function tickClock() {
  document.getElementById("clock").textContent =
    new Date().toLocaleTimeString("en-GB", { hour12: false });
}
setInterval(tickClock, 1000);
tickClock();

// ── Status ──
function setStatus(ok) {
  const badge = document.getElementById("status-badge");
  const text = document.getElementById("status-text");
  badge.className = "status-badge " + (ok ? "online" : "offline");
  text.textContent = ok ? "System Online" : "Offline";
}

// ── Polling ──
let alertFilter = "all";
let lastAlertIds = new Set();

async function poll() {
  try {
    const [stats, alerts, blocked] = await Promise.all([
      apiGet("/stats"), apiGet("/alerts?limit=100"), apiGet("/blocked"),
    ]);
    setStatus(true);
    renderStats(stats, blocked);
    renderAlerts(alerts);
    renderBlocked(blocked);
    renderAttackers(alerts, blocked);
    renderPipeline(stats, blocked);
  } catch (e) {
    if (e.message === "Session expired") return;
    setStatus(false);
  }
}

function renderStats(s, blocked) {
  const inf = s.inference || {};
  const al = s.alerts || {};
  const total = inf.total_predictions || 0;
  const attacks = inf.total_attacks_detected || 0;
  const rate = (inf.attack_rate || 0) * 100;
  const lat = inf.latency_ms || {};

  document.getElementById("m-total").textContent = fmt(total);
  document.getElementById("m-attacks").textContent = fmt(attacks);
  document.getElementById("m-rate").textContent = rate.toFixed(1) + "% attack rate";
  document.getElementById("m-blocked").textContent = blocked.length;
  document.getElementById("m-latency").textContent =
    lat.p50 ? lat.p50.toFixed(1) + "ms" : "—";

  // Severity cards
  const bySev = al.by_severity || {};
  document.querySelectorAll(".sev-card").forEach(el => {
    const sev = el.dataset.sev;
    el.querySelector(".sev-num").textContent = bySev[sev] || 0;
  });

  // Threat breakdown
  const byType = al.by_type || {};
  renderThreatBreakdown(byType);
}

function renderPipeline(s, blocked) {
  const inf = s.inference || {};
  const total = inf.total_predictions || 0;
  const attacks = inf.total_attacks_detected || 0;
  const safe = total - attacks;

  document.getElementById("pipe-traffic").textContent = fmt(total);
  document.getElementById("pipe-analyzed").textContent = fmt(total);
  document.getElementById("pipe-safe").textContent = fmt(safe);
  document.getElementById("pipe-threats").textContent = fmt(attacks);
  document.getElementById("pipe-blocked").textContent = blocked.length;

  // Feed the river animation — only new traffic since last poll
  const newTotal = total - river.total;
  const newAttacks = attacks - river.attacks;
  if (newTotal > 0) {
    river.newSafe += (newTotal - newAttacks);
    river.newAttack += newAttacks;
  }
  river.total = total;
  river.attacks = attacks;
  river.blocked = blocked.length;
}

const SEV_MAP = {
  DDoS: "critical", Botnet: "high", Infiltration: "high",
  BruteForce: "medium", WebAttack: "medium", PortScan: "low",
};

function renderThreatBreakdown(byType) {
  const host = document.getElementById("threat-breakdown");
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    host.innerHTML = '<div class="empty-state">No threats detected yet — try the simulator below</div>';
    return;
  }
  const max = Math.max(...entries.map(e => e[1]));
  host.innerHTML = entries.map(([name, count]) => {
    const pct = (count / max) * 100;
    const sev = SEV_MAP[name] || "medium";
    return `<div class="threat-row" data-type="${name}">
      <div class="threat-name">${name}</div>
      <div class="threat-bar-wrap"><div class="threat-bar ${sev}" style="width:${pct}%"></div></div>
      <div class="threat-count">${count}</div>
    </div>`;
  }).join("");
}

function renderAlerts(alerts) {
  const host = document.getElementById("alert-list");
  document.getElementById("alert-count").textContent = alerts.length;

  let filtered = alerts;
  if (alertFilter !== "all") filtered = alerts.filter(a => a.severity === alertFilter);

  if (!filtered.length) {
    host.innerHTML = '<div class="empty-state">No alerts matching this filter</div>';
    lastAlertIds = new Set(alerts.map(a => a.alert_id));
    return;
  }

  host.innerHTML = filtered.map(a => {
    const isNew = !lastAlertIds.has(a.alert_id);
    return `<div class="alert-entry${isNew ? ' new' : ''}">
      <span class="alert-time">${fmtTime(a.timestamp)}</span>
      <span class="alert-sev ${a.severity}">${a.severity}</span>
      <span class="alert-type">${a.attack_type}</span>
      <span class="alert-conf">${(a.confidence * 100).toFixed(1)}%</span>
      <span class="alert-ip">${a.source_ip || '—'}</span>
    </div>`;
  }).join("");

  lastAlertIds = new Set(alerts.map(a => a.alert_id));
}

function renderBlocked(blocked) {
  const host = document.getElementById("blocked-list");
  document.getElementById("blocked-count").textContent = blocked.length;

  if (!blocked.length) {
    host.innerHTML = '<div class="empty-state">No IPs blocked yet — attacks with high confidence are blocked automatically</div>';
    return;
  }

  const canUnblock = nsRole === "admin";

  host.innerHTML = blocked.map(b => {
    const mins = Math.ceil(b.remaining_seconds / 60);
    const ttl = mins > 60 ? Math.ceil(mins / 60) + "h " + (mins % 60) + "m" : mins + " min";
    const action = b.action_type === "drop" ? "Dropped" : b.action_type === "block" ? "Blocked" : b.action_type;
    const unblockBtn = canUnblock
      ? `<button class="unblock-btn" data-ip="${b.ip_address}">Unblock</button>`
      : '';
    return `<div class="blocked-entry">
      <div class="blocked-info">
        <div class="blocked-ip">${b.ip_address}</div>
        <div class="blocked-meta">
          <span>🚨 ${b.attack_type}</span>
          <span>🎯 ${(b.confidence * 100).toFixed(0)}% confidence</span>
          <span>⏱ ${ttl} remaining</span>
          <span>🔒 ${action}</span>
        </div>
      </div>
      ${unblockBtn}
    </div>`;
  }).join("");

  if (canUnblock) {
    host.querySelectorAll(".unblock-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        try {
          await apiDelete("/blocked/" + encodeURIComponent(btn.dataset.ip));
          poll();
        } catch (e) { console.error(e); }
      });
    });
  }
}

// Aggregate alerts by source IP — a ranked "where attacks come from" list.
function renderAttackers(alerts, blocked) {
  const host = document.getElementById("attacker-list");
  if (!host) return;

  const blockedSet = new Set((blocked || []).map(b => b.ip_address));
  const byIp = new Map();
  for (const a of alerts) {
    const ip = a.source_ip || "unknown";
    let e = byIp.get(ip);
    if (!e) { e = { ip, hits: 0, types: {}, maxConf: 0 }; byIp.set(ip, e); }
    e.hits++;
    e.types[a.attack_type] = (e.types[a.attack_type] || 0) + 1;
    if (a.confidence > e.maxConf) e.maxConf = a.confidence;
  }

  const rows = [...byIp.values()].sort((x, y) => y.hits - x.hits).slice(0, 10);
  if (!rows.length) {
    host.innerHTML = '<div class="empty-state">No traffic yet — source IPs appear here as flows are classified</div>';
    return;
  }

  host.innerHTML = rows.map(e => {
    const topType = Object.entries(e.types).sort((a, b) => b[1] - a[1])[0][0];
    const isBlocked = blockedSet.has(e.ip);
    return `<div class="attacker-entry">
      <span class="attacker-ip">${e.ip}</span>
      <span class="attacker-type">${topType}</span>
      <span class="attacker-hits">${e.hits} hit${e.hits > 1 ? "s" : ""}</span>
      <span class="attacker-conf">${(e.maxConf * 100).toFixed(0)}%</span>
      <span class="attacker-status ${isBlocked ? "blocked" : "seen"}">${isBlocked ? "🛡 blocked" : "seen"}</span>
    </div>`;
  }).join("");
}

// ── Filter buttons ──
document.querySelectorAll(".af").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".af").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    alertFilter = btn.dataset.sev;
    poll();
  });
});

// ── Simulate attack ──
document.getElementById("probe-fire").addEventListener("click", async () => {
  const btn = document.getElementById("probe-fire");
  const preset = document.getElementById("probe-preset").value;
  const source = document.getElementById("probe-source").value.trim() || "203.0.113.42";
  const output = document.getElementById("probe-output");

  btn.disabled = true;
  btn.innerHTML = '<span class="sim-btn-icon">⏳</span> Analyzing…';
  output.innerHTML = '<div class="empty-state">Sending flow to AI model for classification…</div>';

  const flow = jitter(PRESETS[preset] || PRESETS.benign);

  try {
    const res = await apiPost("/predict", { flow, source_ip: source });
    const r = res.result;
    const isAttack = r.is_attack;

    const banner = isAttack
      ? `<div class="result-banner is-attack">🚨 THREAT DETECTED — ${r.prediction} attack identified!</div>`
      : `<div class="result-banner is-safe">✅ SAFE — This traffic looks normal</div>`;

    const blocked = isAttack
      ? `<div class="result-item"><span class="result-key">Action Taken</span><span class="result-val attack">IP ${source} queued for blocking</span></div>`
      : '';

    output.innerHTML = `
      ${banner}
      <div class="result-grid">
        <div class="result-item">
          <span class="result-key">Classification</span>
          <span class="result-val ${isAttack ? 'attack' : 'safe'}">${r.prediction}</span>
        </div>
        <div class="result-item">
          <span class="result-key">Confidence</span>
          <span class="result-val">${(r.confidence * 100).toFixed(1)}%</span>
        </div>
        <div class="result-item">
          <span class="result-key">Anomaly Score</span>
          <span class="result-val">${r.anomaly_score.toFixed(3)}</span>
        </div>
        <div class="result-item">
          <span class="result-key">Detection Speed</span>
          <span class="result-val">${res.total_latency_ms.toFixed(1)} ms</span>
        </div>
        ${isAttack ? `<div class="result-item">
          <span class="result-key">Alert ID</span>
          <span class="result-val attack">${res.alert_id}</span>
        </div>` : ''}
        ${blocked}
      </div>
    `;
    // Spawn river particles for this manual probe instantly
    if (isAttack) { river.newAttack += 1; } else { river.newSafe += 1; }
    addLiveFeedEntry({ source_ip: source, prediction: r.prediction, is_attack: isAttack, confidence: r.confidence });
    poll();
  } catch (e) {
    output.innerHTML = `<div class="result-banner is-attack">Error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="sim-btn-icon">▶</span> Send Traffic';
  }
});

// ── Live capture controls ──
const startBtn = document.getElementById("capture-start-btn");
const stopBtn = document.getElementById("capture-stop-btn");
const captureBar = document.querySelector(".capture-bar");
const liveFeed = document.getElementById("live-feed");

startBtn.addEventListener("click", async () => {
  const iface = document.getElementById("capture-iface").value.trim();
  startBtn.disabled = true;
  startBtn.textContent = "Starting…";
  try {
    const url = iface ? `/capture/start?interface=${encodeURIComponent(iface)}` : "/capture/start";
    await apiPost(url, {});
    startBtn.style.display = "none";
    stopBtn.style.display = "";
    captureBar.classList.add("active");
    liveFeed.style.display = "";
  } catch (e) {
    alert("Failed to start capture: " + e.message + "\n\nMake sure you run with sudo:\n  sudo python3 -m scripts.run_server");
  } finally {
    startBtn.disabled = false;
    startBtn.textContent = "▶ Start Capture";
  }
});

stopBtn.addEventListener("click", async () => {
  try {
    await apiPost("/capture/stop", {});
  } catch (e) { console.error(e); }
  stopBtn.style.display = "none";
  startBtn.style.display = "";
  captureBar.classList.remove("active");
});

// Poll capture status
async function pollCapture() {
  try {
    const cs = await apiGet("/capture/status");
    const statusText = document.getElementById("capture-status-text");
    const detail = document.getElementById("capture-detail");

    if (cs.running) {
      statusText.textContent = "🔴 CAPTURING LIVE";
      detail.textContent = `${fmt(cs.packets_captured)} packets · ${cs.flows_classified} flows classified · ${cs.attacks_detected} attacks`;
      captureBar.classList.add("active");
      startBtn.style.display = "none";
      stopBtn.style.display = "";
      liveFeed.style.display = "";
      document.getElementById("live-feed-count").textContent = `${cs.packets_captured} packets captured`;
    } else {
      statusText.textContent = "Capture Stopped";
      detail.textContent = cs.scapy_available
        ? "Start live capture to monitor real network traffic"
        : "Live capture unavailable (optional scapy package not installed)";
      captureBar.classList.remove("active");
    }
  } catch (e) { /* ignore */ }
}

// ── WebSocket — real-time push from server ─────────────────────────────
let ws = null;
let wsReconnectTimer = null;

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const tokenParam = nsToken ? "?token=" + encodeURIComponent(nsToken) : "";
  ws = new WebSocket(`${proto}//${location.host}/ws${tokenParam}`);

  ws.onopen = () => {
    console.log("WebSocket connected");
    document.getElementById("status-text").textContent = "System Online (live)";
  };

  ws.onmessage = (e) => {
    const event = JSON.parse(e.data);
    if (event.type === "packet") {
      tmPackets++;
      river.newRaw++;
      addTrafficRow(event);
    } else if (event.type === "flow") {
      tmFlows++;
      if (event.is_attack) { tmThreats++; river.newAttack++; } else { tmSafe++; river.newSafe++; }
      addLiveFeedEntry(event);
      updateTrafficStats();
    }
  };

  ws.onclose = () => {
    console.log("WebSocket disconnected, reconnecting...");
    wsReconnectTimer = setTimeout(connectWebSocket, 2000);
  };

  ws.onerror = () => ws.close();
}

function addLiveFeedEntry(event) {
  const feedList = document.getElementById("live-feed-list");
  if (!feedList) return;

  const now = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const cls = event.is_attack ? "attack" : "safe";
  const tag = event.is_attack ? "🚨 " : "✅ ";

  const div = document.createElement("div");
  div.className = "lf-entry";
  div.innerHTML = `
    <span class="lf-time">${now.split(":").slice(1).join(":")}</span>
    <span class="lf-ip">${event.source_ip || "—"}</span>
    <span class="lf-pred ${cls}">${tag}${event.prediction}</span>
    <span class="lf-conf">${(event.confidence * 100).toFixed(0)}%</span>
  `;

  feedList.insertBefore(div, feedList.firstChild);

  // Keep max 50 entries
  while (feedList.children.length > 50) {
    feedList.removeChild(feedList.lastChild);
  }
}

connectWebSocket();

// ── Live Traffic Table ─────────────────────────────────────────────────
let tmPackets = 0, tmFlows = 0, tmSafe = 0, tmThreats = 0;
const trafficTbody = document.getElementById("traffic-tbody");
const MAX_TRAFFIC_ROWS = 500;

function updateTrafficStats() {
  const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = fmt(v); };
  el("tm-packets", tmPackets);
  el("tm-flows", tmFlows);
  el("tm-safe", tmSafe);
  el("tm-threats", tmThreats);
}

function addTrafficRow(pkt) {
  if (!trafficTbody) return;
  const now = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const tr = document.createElement("tr");
  tr.innerHTML =
    `<td class="tt-time">${now}</td>` +
    `<td class="tt-addr">${pkt.src_ip}:${pkt.src_port}</td>` +
    `<td class="tt-addr">${pkt.dst_ip}:${pkt.dst_port}</td>` +
    `<td class="tt-proto">${pkt.proto}</td>` +
    `<td class="tt-size">${pkt.size} B</td>` +
    `<td class="tt-result">-</td>`;
  trafficTbody.insertBefore(tr, trafficTbody.firstChild);
  while (trafficTbody.children.length > MAX_TRAFFIC_ROWS) {
    trafficTbody.removeChild(trafficTbody.lastChild);
  }
  if (tmPackets % 50 === 0) updateTrafficStats();
}

// ── River Animation ────────────────────────────────────────────────────
const riverCanvas = document.getElementById("river-canvas");
const riverCtx = riverCanvas ? riverCanvas.getContext("2d") : null;

const MAIN_Y = 0.5;
const SAFE_Y = 0.28;
const THREAT_Y = 0.72;

class Particle {
  constructor(type) {
    this.type = type;
    this.progress = 0;
    this.speed = 0.003 + Math.random() * 0.004;
    this.size = 2 + Math.random() * 3;
    this.opacity = 0.6 + Math.random() * 0.4;
    this.phase = Math.random() * Math.PI * 2;
    this.x = 0;
    this.y = 0;
    this.done = false;
  }

  update() {
    this.progress += this.speed;
    if (this.progress >= 1) { this.done = true; return; }

    const w = riverCanvas.width;
    const h = riverCanvas.height;
    const inX = w * 0.08;
    const modelX = w * 0.35;
    const splitX = w * 0.65;
    const endX = w * 0.92;
    const mainY = h * MAIN_Y;
    const safeY = h * SAFE_Y;
    const threatY = h * THREAT_Y;
    const wave = Math.sin(this.phase + this.progress * 20) * 4;

    if (this.progress < 0.4) {
      const t = this.progress / 0.4;
      this.x = inX + (modelX - inX) * t;
      this.y = mainY + wave;
    } else if (this.progress < 0.7) {
      const t = (this.progress - 0.4) / 0.3;
      this.x = modelX + (splitX - modelX) * t;
      if (this.type === "attack") {
        this.y = mainY + (threatY - mainY) * t + wave * 0.7;
      } else {
        this.y = mainY + (safeY - mainY) * t + wave * 0.7;
      }
    } else {
      const t = (this.progress - 0.7) / 0.3;
      this.x = splitX + (endX - splitX) * t;
      if (this.type === "attack") {
        this.y = threatY + wave * 0.5;
      } else {
        this.y = safeY + wave * 0.5;
        this.opacity = (0.6 + Math.random() * 0.2) * (1 - t * 0.4);
      }
    }
  }

  draw(ctx) {
    if (this.done) return;
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    if (this.type === "attack") {
      ctx.fillStyle = `rgba(248, 113, 113, ${this.opacity})`;
      ctx.shadowColor = "rgba(248, 113, 113, 0.4)";
    } else {
      ctx.fillStyle = `rgba(52, 211, 153, ${this.opacity})`;
      ctx.shadowColor = "rgba(52, 211, 153, 0.4)";
    }
    ctx.shadowBlur = 6;
    ctx.fill();
    ctx.shadowBlur = 0;
  }
}

function resizeCanvas() {
  if (!riverCanvas) return;
  const rect = riverCanvas.parentElement.getBoundingClientRect();
  riverCanvas.width = rect.width;
  riverCanvas.height = rect.height;
}

function spawnParticles() {
  while (river.newSafe > 0) { river.particles.push(new Particle("safe")); river.newSafe--; }
  while (river.newAttack > 0) { river.particles.push(new Particle("attack")); river.newAttack--; }
  while (river.newRaw > 0) { river.particles.push(new Particle("raw")); river.newRaw--; }
}

function drawRiverPaths(ctx, w, h) {
  const inX = w * 0.08, modelX = w * 0.35, splitX = w * 0.65, endX = w * 0.92;
  const mainY = h * MAIN_Y, safeY = h * SAFE_Y, threatY = h * THREAT_Y;

  ctx.lineWidth = 2;

  ctx.strokeStyle = "rgba(52, 211, 153, 0.1)";
  ctx.beginPath();
  ctx.moveTo(inX, mainY);
  ctx.lineTo(modelX, mainY);
  ctx.stroke();

  ctx.beginPath();
  ctx.moveTo(modelX, mainY);
  ctx.quadraticCurveTo((modelX + splitX) / 2, mainY, splitX, safeY);
  ctx.lineTo(endX, safeY);
  ctx.stroke();

  ctx.strokeStyle = "rgba(248, 113, 113, 0.1)";
  ctx.beginPath();
  ctx.moveTo(modelX, mainY);
  ctx.quadraticCurveTo((modelX + splitX) / 2, mainY, splitX, threatY);
  ctx.lineTo(endX, threatY);
  ctx.stroke();
}

function animateRiver() {
  if (!riverCanvas || !riverCtx) return;

  const w = riverCanvas.width;
  const h = riverCanvas.height;

  riverCtx.clearRect(0, 0, w, h);
  drawRiverPaths(riverCtx, w, h);
  spawnParticles();

  for (let i = river.particles.length - 1; i >= 0; i--) {
    river.particles[i].update();
    river.particles[i].draw(riverCtx);
    if (river.particles[i].done) river.particles.splice(i, 1);
  }

  const stIn = document.getElementById("st-in-count");
  const stModel = document.getElementById("st-model-count");
  const stSafe = document.getElementById("st-safe-count");
  const stThreat = document.getElementById("st-threat-count");
  const stBlocked = document.getElementById("st-blocked-count");

  if (stIn) stIn.textContent = fmt(river.total);
  if (stModel) stModel.textContent = fmt(river.total);
  if (stSafe) stSafe.textContent = fmt(river.total - river.attacks);
  if (stThreat) stThreat.textContent = fmt(river.attacks);
  if (stBlocked) stBlocked.textContent = fmt(river.blocked);

  requestAnimationFrame(animateRiver);
}

window.addEventListener("resize", resizeCanvas);
resizeCanvas();
animateRiver();

// ── Boot ──
poll();
pollCapture();
setInterval(poll, POLL_MS);
setInterval(pollCapture, POLL_MS);
