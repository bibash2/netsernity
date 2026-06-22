/* NetSentry operator console — client side
   Polls the API, renders telemetry, and fires manual probes. */

const API = "/api/v1";
const POLL_MS = 2500;

// -------- Preset flow profiles (approximate signatures per class) --------
const PRESETS = {
  benign: {
    flow_duration: 180000, total_fwd_packets: 20, total_bwd_packets: 18,
    fwd_packet_length_mean: 500, bwd_packet_length_mean: 700,
    flow_bytes_per_sec: 20000, flow_packets_per_sec: 50,
    fwd_iat_mean: 15000, bwd_iat_mean: 20000, fwd_iat_std: 5000,
    packet_length_mean: 600, packet_length_std: 150, packet_length_variance: 22500,
    fin_flag_count: 1, syn_flag_count: 1, rst_flag_count: 0,
    psh_flag_count: 4, ack_flag_count: 20, urg_flag_count: 0,
    down_up_ratio: 1.2, avg_packet_size: 600, fwd_segment_size_avg: 500,
    bwd_segment_size_avg: 700, subflow_fwd_packets: 20, subflow_bwd_packets: 18,
    init_win_bytes_fwd: 32000, init_win_bytes_bwd: 32000,
    active_mean: 20000, idle_mean: 60000, fwd_header_length: 400,
  },
  ddos: {
    flow_duration: 6000, total_fwd_packets: 5000, total_bwd_packets: 3,
    fwd_packet_length_mean: 60, bwd_packet_length_mean: 0,
    flow_bytes_per_sec: 5000000, flow_packets_per_sec: 80000,
    fwd_iat_mean: 1.2, bwd_iat_mean: 0, fwd_iat_std: 0.4,
    packet_length_mean: 60, packet_length_std: 5, packet_length_variance: 25,
    fin_flag_count: 0, syn_flag_count: 3000, rst_flag_count: 10,
    psh_flag_count: 0, ack_flag_count: 10, urg_flag_count: 0,
    down_up_ratio: 0.01, avg_packet_size: 60, fwd_segment_size_avg: 60,
    bwd_segment_size_avg: 0, subflow_fwd_packets: 5000, subflow_bwd_packets: 3,
    init_win_bytes_fwd: 512, init_win_bytes_bwd: 64,
    active_mean: 2000, idle_mean: 1000, fwd_header_length: 100000,
  },
  portscan: {
    flow_duration: 200, total_fwd_packets: 2, total_bwd_packets: 1,
    fwd_packet_length_mean: 40, bwd_packet_length_mean: 40,
    flow_bytes_per_sec: 20000, flow_packets_per_sec: 15000,
    fwd_iat_mean: 100, bwd_iat_mean: 100, fwd_iat_std: 10,
    packet_length_mean: 40, packet_length_std: 0, packet_length_variance: 0,
    fin_flag_count: 0, syn_flag_count: 2, rst_flag_count: 2,
    psh_flag_count: 0, ack_flag_count: 1, urg_flag_count: 0,
    down_up_ratio: 0.1, avg_packet_size: 40, fwd_segment_size_avg: 40,
    bwd_segment_size_avg: 40, subflow_fwd_packets: 2, subflow_bwd_packets: 1,
    init_win_bytes_fwd: 0, init_win_bytes_bwd: 0,
    active_mean: 100, idle_mean: 50, fwd_header_length: 40,
  },
  bruteforce: {
    flow_duration: 45000000, total_fwd_packets: 200, total_bwd_packets: 180,
    fwd_packet_length_mean: 120, bwd_packet_length_mean: 150,
    flow_bytes_per_sec: 3000, flow_packets_per_sec: 9,
    fwd_iat_mean: 220000, bwd_iat_mean: 240000, fwd_iat_std: 80000,
    packet_length_mean: 130, packet_length_std: 20, packet_length_variance: 400,
    fin_flag_count: 2, syn_flag_count: 2, rst_flag_count: 2,
    psh_flag_count: 120, ack_flag_count: 180, urg_flag_count: 0,
    down_up_ratio: 1.0, avg_packet_size: 130, fwd_segment_size_avg: 120,
    bwd_segment_size_avg: 150, subflow_fwd_packets: 200, subflow_bwd_packets: 180,
    init_win_bytes_fwd: 32000, init_win_bytes_bwd: 32000,
    active_mean: 500000, idle_mean: 1000000, fwd_header_length: 4000,
  },
  botnet: {
    flow_duration: 900000, total_fwd_packets: 12, total_bwd_packets: 10,
    fwd_packet_length_mean: 180, bwd_packet_length_mean: 280,
    flow_bytes_per_sec: 3500, flow_packets_per_sec: 12,
    fwd_iat_mean: 60000, bwd_iat_mean: 70000, fwd_iat_std: 20000,
    packet_length_mean: 220, packet_length_std: 40, packet_length_variance: 1600,
    fin_flag_count: 1, syn_flag_count: 1, rst_flag_count: 0,
    psh_flag_count: 4, ack_flag_count: 18, urg_flag_count: 0,
    down_up_ratio: 1.8, avg_packet_size: 220, fwd_segment_size_avg: 180,
    bwd_segment_size_avg: 280, subflow_fwd_packets: 12, subflow_bwd_packets: 10,
    init_win_bytes_fwd: 16000, init_win_bytes_bwd: 16000,
    active_mean: 100000, idle_mean: 500000, fwd_header_length: 240,
  },
  infiltration: {
    flow_duration: 25000000, total_fwd_packets: 80, total_bwd_packets: 70,
    fwd_packet_length_mean: 800, bwd_packet_length_mean: 900,
    flow_bytes_per_sec: 50000, flow_packets_per_sec: 20,
    fwd_iat_mean: 200000, bwd_iat_mean: 220000, fwd_iat_std: 60000,
    packet_length_mean: 850, packet_length_std: 150, packet_length_variance: 22500,
    fin_flag_count: 1, syn_flag_count: 2, rst_flag_count: 1,
    psh_flag_count: 20, ack_flag_count: 80, urg_flag_count: 0,
    down_up_ratio: 1.3, avg_packet_size: 850, fwd_segment_size_avg: 800,
    bwd_segment_size_avg: 900, subflow_fwd_packets: 80, subflow_bwd_packets: 70,
    init_win_bytes_fwd: 40000, init_win_bytes_bwd: 40000,
    active_mean: 1000000, idle_mean: 2000000, fwd_header_length: 1600,
  },
  webattack: {
    flow_duration: 500000, total_fwd_packets: 25, total_bwd_packets: 30,
    fwd_packet_length_mean: 700, bwd_packet_length_mean: 1200,
    flow_bytes_per_sec: 150000, flow_packets_per_sec: 100,
    fwd_iat_mean: 20000, bwd_iat_mean: 25000, fwd_iat_std: 8000,
    packet_length_mean: 950, packet_length_std: 200, packet_length_variance: 40000,
    fin_flag_count: 1, syn_flag_count: 2, rst_flag_count: 0,
    psh_flag_count: 20, ack_flag_count: 50, urg_flag_count: 0,
    down_up_ratio: 1.5, avg_packet_size: 950, fwd_segment_size_avg: 700,
    bwd_segment_size_avg: 1200, subflow_fwd_packets: 25, subflow_bwd_packets: 30,
    init_win_bytes_fwd: 32000, init_win_bytes_bwd: 32000,
    active_mean: 100000, idle_mean: 200000, fwd_header_length: 500,
  },
};

// -------- Helpers --------
function jitter(flow) {
  const out = {};
  for (const k in flow) {
    const v = flow[k];
    // add up to +/-8% random jitter so repeated fires aren't identical
    const j = (Math.random() - 0.5) * 0.16;
    out[k] = Math.max(0, v * (1 + j));
  }
  return out;
}

function formatNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(n);
}

function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

async function apiGet(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.json();
}

async function apiPost(path, body) {
  const r = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${path} → ${r.status}: ${await r.text()}`);
  return r.json();
}

// -------- Status + clock --------
function tickClock() {
  const d = new Date();
  const s = d.toLocaleTimeString("en-GB", { hour12: false });
  document.getElementById("clock").textContent = s + "Z";
}
setInterval(tickClock, 1000);
tickClock();

function setStatus(ok, label) {
  const pill = document.getElementById("status-pill");
  const text = document.getElementById("status-text");
  pill.classList.remove("ok", "err");
  pill.classList.add(ok ? "ok" : "err");
  text.textContent = label;
}

// -------- Poll stats and alerts --------
let alertFilter = "all";

async function poll() {
  try {
    const [stats, alerts] = await Promise.all([
      apiGet("/stats"),
      apiGet("/alerts?limit=100"),
    ]);
    setStatus(true, "online");
    renderStats(stats);
    renderAlerts(alerts);
  } catch (e) {
    setStatus(false, "offline");
    console.error(e);
  }
}

function renderStats(s) {
  const inf = s.inference || {};
  const al = s.alerts || {};
  document.getElementById("stat-preds").textContent = formatNum(inf.total_predictions || 0);
  document.getElementById("stat-attacks").textContent = formatNum(inf.total_attacks_detected || 0);
  const rate = (inf.attack_rate || 0) * 100;
  document.getElementById("stat-rate").textContent = rate.toFixed(2) + "%";
  const lat = inf.latency_ms || {};
  document.getElementById("stat-p50").textContent = (lat.p50 || 0).toFixed(1) + " ms";
  document.getElementById("stat-p95").textContent = (lat.p95 || 0).toFixed(1) + " ms";
  document.getElementById("stat-p99").textContent = (lat.p99 || 0).toFixed(1) + " ms";

  // severity counts
  const bySev = al.by_severity || {};
  document.querySelectorAll(".sev-block").forEach(el => {
    const sev = el.dataset.sev;
    el.querySelector(".sev-count").textContent = bySev[sev] || 0;
  });

  // distribution
  const byType = al.by_type || {};
  renderDistribution(byType);
}

function renderDistribution(byType) {
  const host = document.getElementById("distribution-chart");
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    host.innerHTML = '<div class="muted">// awaiting traffic…</div>';
    return;
  }
  const max = Math.max(...entries.map(e => e[1]));
  host.innerHTML = entries.map(([name, count]) => {
    const pct = (count / max) * 100;
    return `
      <div class="dist-row">
        <div class="dist-label">${name}</div>
        <div class="dist-bar"><div class="dist-bar-fill" style="width:${pct}%"></div></div>
        <div class="dist-count">${count}</div>
      </div>`;
  }).join("");
}

let lastAlertIds = new Set();

function renderAlerts(alerts) {
  const host = document.getElementById("alert-list");
  document.getElementById("alert-count").textContent = alerts.length;

  let filtered = alerts;
  if (alertFilter !== "all") filtered = alerts.filter(a => a.severity === alertFilter);

  if (filtered.length === 0) {
    host.innerHTML = '<div class="muted center">// no alerts matching filter</div>';
    lastAlertIds = new Set(alerts.map(a => a.alert_id));
    return;
  }

  host.innerHTML = filtered.map(a => {
    const isNew = !lastAlertIds.has(a.alert_id);
    return `
      <div class="alert-row${isNew ? ' new' : ''}">
        <span class="time">${formatTime(a.timestamp)}</span>
        <span class="sev ${a.severity}">${a.severity}</span>
        <span class="type">${a.attack_type}</span>
        <span class="conf">${(a.confidence * 100).toFixed(1)}%</span>
        <span class="src">${a.source_ip || '—'}</span>
        <span class="action">${a.recommended_action.replace(/_/g, ' ')}</span>
      </div>`;
  }).join("");

  lastAlertIds = new Set(alerts.map(a => a.alert_id));
}

// -------- Filter bar --------
document.querySelectorAll(".filter").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    alertFilter = btn.dataset.sev;
    poll();
  });
});

// -------- Manual probe --------
document.getElementById("probe-fire").addEventListener("click", async () => {
  const btn = document.getElementById("probe-fire");
  const preset = document.getElementById("probe-preset").value;
  const source = document.getElementById("probe-source").value.trim() || null;
  const output = document.getElementById("probe-output");
  btn.disabled = true;
  btn.textContent = "◌ FIRING…";
  output.innerHTML = '<div class="line head">// transmitting flow…</div>';

  const flow = jitter(PRESETS[preset] || PRESETS.benign);

  try {
    const res = await apiPost("/predict", { flow, source_ip: source });
    const r = res.result;
    const lines = [
      `<div class="line head">// RESPONSE</div>`,
      `<div class="line"><span class="key">prediction</span>: ${r.prediction}</div>`,
      `<div class="line"><span class="key">is_attack</span>: ${r.is_attack ? '<span class="err">true</span>' : '<span class="ok">false</span>'}</div>`,
      `<div class="line"><span class="key">confidence</span>: ${(r.confidence * 100).toFixed(2)}%</div>`,
      `<div class="line"><span class="key">anomaly_score</span>: ${r.anomaly_score.toFixed(4)} ${r.anomaly_flagged ? '(flagged)' : ''}</div>`,
      `<div class="line"><span class="key">latency</span>: ${res.total_latency_ms.toFixed(1)} ms</div>`,
      res.alert_id ? `<div class="line ok"><span class="key">alert</span>: ${res.alert_id} emitted</div>` : '',
    ];
    output.innerHTML = lines.filter(Boolean).join("");
    poll();  // refresh stats right away
  } catch (e) {
    output.innerHTML = `<div class="line err">// error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "► FIRE PROBE";
  }
});

// -------- Boot --------
poll();
setInterval(poll, POLL_MS);
