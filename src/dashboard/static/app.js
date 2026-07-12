/* NetSentry Dashboard — user-friendly real-time monitoring */

const API = "/api/v1";
const POLL_MS = 2000;

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

async function apiGet(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(API + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
  return r.json();
}
async function apiDelete(path) {
  const r = await fetch(API + path, { method: "DELETE" });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

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
    renderPipeline(stats, blocked);
  } catch (e) {
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

  host.innerHTML = blocked.map(b => {
    const mins = Math.ceil(b.remaining_seconds / 60);
    const ttl = mins > 60 ? Math.ceil(mins / 60) + "h " + (mins % 60) + "m" : mins + " min";
    const action = b.action_type === "drop" ? "Dropped" : b.action_type === "block" ? "Blocked" : b.action_type;
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
      <button class="unblock-btn" data-ip="${b.ip_address}">Unblock</button>
    </div>`;
  }).join("");

  host.querySelectorAll(".unblock-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      try {
        await apiDelete("/blocked/" + encodeURIComponent(btn.dataset.ip));
        poll();
      } catch (e) { console.error(e); }
    });
  });
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

      // Live feed entries now pushed via WebSocket — no polling needed
    } else {
      statusText.textContent = "Capture Stopped";
      detail.textContent = cs.scapy_available
        ? "Start live capture to monitor real network traffic"
        : "⚠ scapy not installed — run: pip install scapy";
      captureBar.classList.remove("active");
    }
  } catch (e) { /* ignore */ }
}

// ── WebSocket — real-time push from server ─────────────────────────────
let ws = null;
let wsReconnectTimer = null;

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    console.log("WebSocket connected");
    document.getElementById("status-text").textContent = "System Online (live)";
  };

  ws.onmessage = (e) => {
    const event = JSON.parse(e.data);
    if (event.type === "packets") {
      // Raw packets arriving — show as unclassified (blue) dots entering the river
      river.newRaw += event.count;
    } else if (event.type === "flow") {
      // Classified flow — show colored particle (green safe / red attack)
      if (event.is_attack) {
        river.newAttack += 1;
      } else {
        river.newSafe += 1;
      }
      addLiveFeedEntry(event);
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

// ── Animated River ──────────────────────────────────────────────────────
const canvas = document.getElementById("river-canvas");
const ctx = canvas.getContext("2d");

// Particle pool
const particles = [];
const MAX_PARTICLES = 200;

// River state — only spawns when real traffic arrives
const river = { total: 0, attacks: 0, blocked: 0, prevTotal: 0, prevAttacks: 0, newSafe: 0, newAttack: 0, newRaw: 0 };

// Station X positions (fractions of canvas width)
const STATIONS = {
  inX: 0.08,    // Traffic In
  aiX: 0.30,    // AI Analysis
  forkX: 0.52,  // Decision fork
  safeX: 0.75,  // Safe exit (top)
  threatX: 0.75, // Threat (bottom)
  blockX: 0.92,  // Blocked (bottom)
};

// River Y paths
const MAIN_Y = 0.35;   // main river line (fraction of height)
const SAFE_Y = 0.25;   // safe branch goes up
const THREAT_Y = 0.65;  // threat branch goes down
const BLOCK_Y = 0.65;

function resizeCanvas() {
  canvas.width = canvas.offsetWidth * (window.devicePixelRatio || 1);
  canvas.height = canvas.offsetHeight * (window.devicePixelRatio || 1);
  ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
}
resizeCanvas();
window.addEventListener("resize", resizeCanvas);

// Particle types: "raw" (unclassified incoming), "safe" (benign), "attack" (threat)
class Particle {
  constructor(type) {
    // type: "raw" | "safe" | "attack"
    this.type = type;
    this.x = 0;
    this.y = 0;
    this.progress = 0;
    this.speed = type === "raw"
      ? 0.006 + Math.random() * 0.006   // raw packets move faster (short path)
      : 0.003 + Math.random() * 0.004;
    this.size = type === "raw" ? 2 + Math.random() * 1.5 : 2.5 + Math.random() * 2;
    this.opacity = 0.6 + Math.random() * 0.4;
    this.yOffset = (Math.random() - 0.5) * 20;
    this.phase = Math.random() * Math.PI * 2;
    this.alive = true;
  }

  update(w, h) {
    this.progress += this.speed;

    // Raw packets only travel from start to AI station (first ~52% of river)
    if (this.type === "raw") {
      if (this.progress > STATIONS.forkX) { this.alive = false; return; }
      this.x = this.progress * w;
      const wave = Math.sin(this.phase + this.progress * 10) * 3;
      this.y = MAIN_Y * h + this.yOffset + wave;
      // Fade
      if (this.progress < 0.03) this.opacity = this.progress / 0.03;
      else if (this.progress > STATIONS.forkX - 0.05)
        this.opacity = (STATIONS.forkX - this.progress) / 0.05;
      return;
    }

    // Classified particles: start from AI station, branch to safe/threat
    if (this.progress > 1) { this.alive = false; return; }

    const p = this.progress;
    const wave = Math.sin(this.phase + p * 8) * 4;

    if (p < STATIONS.forkX) {
      this.x = p * w;
      this.y = MAIN_Y * h + this.yOffset + wave;
    } else {
      const branchP = (p - STATIONS.forkX) / (1 - STATIONS.forkX);
      if (this.type === "attack") {
        const targetY = THREAT_Y * h;
        const startY = MAIN_Y * h;
        this.y = startY + (targetY - startY) * Math.min(branchP * 2, 1) + wave * 0.5;
        this.x = (STATIONS.forkX + branchP * (1 - STATIONS.forkX)) * w;
      } else {
        const targetY = SAFE_Y * h;
        const startY = MAIN_Y * h;
        this.y = startY + (targetY - startY) * Math.min(branchP * 2, 1) + wave * 0.5;
        this.x = (STATIONS.forkX + branchP * (1 - STATIONS.forkX)) * w;
      }
    }

    if (p < 0.05) this.opacity = p / 0.05;
    else if (p > 0.9) this.opacity = (1 - p) / 0.1;
  }

  draw(ctx) {
    if (!this.alive) return;
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);

    if (this.type === "attack") {
      ctx.fillStyle = `rgba(248, 113, 113, ${this.opacity})`;
      ctx.shadowColor = "rgba(248, 113, 113, 0.6)";
    } else if (this.type === "safe") {
      ctx.fillStyle = `rgba(52, 211, 153, ${this.opacity})`;
      ctx.shadowColor = "rgba(52, 211, 153, 0.4)";
    } else {
      // Raw/unclassified — white/blue
      ctx.fillStyle = `rgba(96, 165, 250, ${this.opacity * 0.7})`;
      ctx.shadowColor = "rgba(96, 165, 250, 0.3)";
    }
    ctx.shadowBlur = 6;
    ctx.fill();
    ctx.shadowBlur = 0;
  }
}

function spawnParticles() {
  // Raw packets — blue dots flowing into the AI station
  const newRaw = river.newRaw;
  river.newRaw = 0;
  for (let i = 0; i < Math.min(newRaw, 10) && particles.length < MAX_PARTICLES; i++) {
    particles.push(new Particle("raw"));
  }

  // Classified flows — green/red dots from AI station onward
  const newSafe = river.newSafe;
  const newAttack = river.newAttack;
  river.newSafe = 0;
  river.newAttack = 0;
  for (let i = 0; i < newSafe * 3 && particles.length < MAX_PARTICLES; i++) {
    particles.push(new Particle("safe"));
  }
  for (let i = 0; i < newAttack * 3 && particles.length < MAX_PARTICLES; i++) {
    particles.push(new Particle("attack"));
  }
}

function drawRiverPaths(w, h) {
  // Main river path (faint glow line)
  ctx.beginPath();
  ctx.moveTo(0, MAIN_Y * h);
  ctx.lineTo(STATIONS.forkX * w, MAIN_Y * h);
  ctx.strokeStyle = "rgba(52, 211, 153, 0.08)";
  ctx.lineWidth = 30;
  ctx.stroke();

  // Safe branch
  ctx.beginPath();
  ctx.moveTo(STATIONS.forkX * w, MAIN_Y * h);
  ctx.quadraticCurveTo(STATIONS.forkX * w + 60, SAFE_Y * h, w, SAFE_Y * h);
  ctx.strokeStyle = "rgba(52, 211, 153, 0.06)";
  ctx.lineWidth = 20;
  ctx.stroke();

  // Threat branch
  ctx.beginPath();
  ctx.moveTo(STATIONS.forkX * w, MAIN_Y * h);
  ctx.quadraticCurveTo(STATIONS.forkX * w + 60, THREAT_Y * h, w, THREAT_Y * h);
  ctx.strokeStyle = "rgba(248, 113, 113, 0.06)";
  ctx.lineWidth = 16;
  ctx.stroke();

  // Fork point glow
  ctx.beginPath();
  ctx.arc(STATIONS.forkX * w, MAIN_Y * h, 6, 0, Math.PI * 2);
  ctx.fillStyle = "rgba(96, 165, 250, 0.3)";
  ctx.fill();

  // Station markers (subtle dots on the path)
  const stationPositions = [
    { x: STATIONS.inX, y: MAIN_Y },
    { x: STATIONS.aiX, y: MAIN_Y },
    { x: STATIONS.safeX, y: SAFE_Y },
    { x: STATIONS.threatX, y: THREAT_Y },
    { x: STATIONS.blockX, y: BLOCK_Y },
  ];
  for (const s of stationPositions) {
    ctx.beginPath();
    ctx.arc(s.x * w, s.y * h, 3, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(148, 163, 184, 0.2)";
    ctx.fill();
  }
}

function animateRiver() {
  const w = canvas.offsetWidth;
  const h = canvas.offsetHeight;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Draw path lines
  drawRiverPaths(w, h);

  // Spawn new particles
  spawnParticles();

  // Update and draw particles
  for (let i = particles.length - 1; i >= 0; i--) {
    particles[i].update(w, h);
    if (!particles[i].alive) {
      particles.splice(i, 1);
    } else {
      particles[i].draw(ctx);
    }
  }

  requestAnimationFrame(animateRiver);
}

// Start animation
animateRiver();

// ── Boot ──
poll();
pollCapture();
setInterval(poll, POLL_MS);
setInterval(pollCapture, POLL_MS);
