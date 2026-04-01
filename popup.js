"use strict";

let currentHostname = null;
let currentTab = "alerts";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function esc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const TYPE_LABELS = {
  SSL_STRIPPING:             "SSL Stripping",
  HTTPS_DOWNGRADE:           "HTTPS Downgrade",
  REDIRECT_HTTPS_TO_HTTP:    "HTTPS→HTTP Redirect",
  HSTS_REMOVED:              "HSTS Header Stripped",
  SERVER_HEADER_CHANGE:      "Server Header Changed",
  MIXED_CONTENT:             "Mixed Content",
  HIGH_VALUE_HTTP:           "High-Value Site Over HTTP",
  SUSPICIOUS_INLINE_SCRIPT:  "Suspicious Inline Script",
  INSECURE_SCRIPT:           "Insecure Script Source",
  BLOCKED_INSECURE_SCRIPT:   "Insecure Script BLOCKED",
  DATA_URI_SCRIPT:           "Data: URI Script",
  SUSPICIOUS_IFRAME:         "Suspicious Cross-Origin Iframe",
  INSECURE_IFRAME:           "Insecure Iframe",
  BLOCKED_INSECURE_IFRAME:   "Insecure Iframe BLOCKED",
  BLOCKED_INSECURE_FORM:     "Insecure Form BLOCKED",
  BLOCKED_CREDENTIALS_OVER_HTTP: "Credential Leak BLOCKED"
};

// ─── Render Alerts ────────────────────────────────────────────────────────────

function renderAlerts(alerts) {
  const list = document.getElementById("alertsList");
  list.innerHTML = "";

  if (!alerts || alerts.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="icon">✅</div>
        <p><strong>No alerts</strong><br>MITM Detector is watching for threats in real time.</p>
      </div>`;
    return;
  }

  for (const alert of alerts) {
    const isBlocked = !!alert.blocked;
    const card = document.createElement("div");
    card.className = `alert-card ${alert.severity || "medium"}${alert.read ? "" : " unread"}${isBlocked ? " blocked-card" : ""}`;
    card.innerHTML = `
      <div class="alert-header">
        <span class="sev-badge ${alert.severity}">${(alert.severity || "?").toUpperCase()}</span>
        ${isBlocked ? '<span class="blocked-badge">BLOCKED</span>' : ""}
        <span class="alert-type">${esc(TYPE_LABELS[alert.type] || alert.type)}</span>
        <span class="alert-time">${timeAgo(alert.timestamp)}</span>
      </div>
      <div class="alert-msg">${esc(alert.message)}</div>
      ${alert.hostname ? `<div class="alert-host">${esc(alert.hostname)}</div>` : ""}
    `;
    list.appendChild(card);
  }
}

// ─── Update Stats ─────────────────────────────────────────────────────────────

function updateStats(stats) {
  document.getElementById("statCritical").textContent = stats.criticalAlerts  || 0;
  document.getElementById("statBlocked").textContent  = stats.blockedAttacks  || 0;
  document.getElementById("statHosts").textContent    = stats.trackedHosts    || 0;

  const pill     = document.getElementById("statusPill");
  const pillText = document.getElementById("statusText");

  if (!stats.preventionEnabled) {
    pill.className = "status-pill inactive";
    pillText.textContent = "Detect Only";
  } else if (stats.criticalAlerts > 0) {
    pill.className = "status-pill alert";
    pillText.textContent = "Threat Detected";
  } else {
    pill.className = "status-pill active";
    pillText.textContent = "Protected";
  }
}

// ─── Update Page Info ─────────────────────────────────────────────────────────

function updatePageInfo(tab) {
  const badge = document.getElementById("protoBadge");
  const hn    = document.getElementById("curHost");
  if (!tab?.url) { hn.textContent = "—"; badge.textContent = "?"; badge.className = "protocol-badge"; return; }
  try {
    const u = new URL(tab.url);
    currentHostname = u.hostname;
    hn.textContent  = currentHostname;
    const proto = u.protocol.replace(":", "").toUpperCase();
    badge.textContent = proto;
    badge.className   = `protocol-badge ${u.protocol === "https:" ? "https" : "http"}`;
  } catch (_) {
    hn.textContent = tab.url.substring(0, 40);
    badge.textContent = "?"; badge.className = "protocol-badge";
  }
}

// ─── Render Host Info ─────────────────────────────────────────────────────────

function renderHostInfo(info, rtcData, hostname) {
  const panel = document.getElementById("hostPanel");
  panel.innerHTML = "";

  function row(label, value, cls = "") {
    const d = document.createElement("div");
    d.className = "info-row";
    d.innerHTML = `<span class="lbl">${esc(label)}</span><span class="val ${cls}">${esc(String(value))}</span>`;
    return d;
  }

  if (!hostname) { panel.appendChild(row("Status", "No active tab")); return; }
  if (!info)     { panel.appendChild(row("Status", "No data yet — visit this site", "warn")); panel.appendChild(row("Hostname", hostname)); return; }

  panel.appendChild(row("Hostname", hostname));
  panel.appendChild(row("Protocol", info.scheme ? info.scheme.toUpperCase() : "?", info.scheme === "https" ? "good" : "bad"));
  panel.appendChild(row("First Seen", info.firstSeen ? new Date(info.firstSeen).toLocaleDateString() : "—"));
  panel.appendChild(row("Visit Count", info.visitCount || 0));
  panel.appendChild(row("Trusted", info.trusted ? "Yes (manually)" : "No", info.trusted ? "good" : ""));

  if (info.fingerprint) {
    try {
      const fp = JSON.parse(info.fingerprint);
      panel.appendChild(row("HSTS", fp.hasHSTS ? "Present" : "Missing", fp.hasHSTS ? "good" : "warn"));
      panel.appendChild(row("Expect-CT", fp.hasExpectCT ? "Present" : "Not seen"));
      if (fp.server) panel.appendChild(row("Server", fp.server));
    } catch (_) {}
  }

  if (rtcData?.ips?.length > 0) {
    panel.appendChild(row("WebRTC IPs Exposed", rtcData.ips.join(", "), "warn"));
  }
}

// ─── Settings ─────────────────────────────────────────────────────────────────

async function loadSettings() {
  const s = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
  if (!s) return;
  document.getElementById("togglePrevention").checked = s.preventionEnabled;
  document.getElementById("toggleUpgrade").checked    = s.upgradeHTTPS;
  document.getElementById("toggleBlockPage").checked  = s.showBlockingPage;
  document.getElementById("toggleBlockSub").checked   = s.blockInsecureSubResources;
  document.getElementById("toggleNotify").checked     = s.notifyOnBlock;
  updateTogglesDisabledState(s.preventionEnabled);
}

function updateTogglesDisabledState(preventionOn) {
  ["toggleUpgrade", "toggleBlockPage", "toggleBlockSub", "toggleNotify"].forEach(id => {
    document.getElementById(id).disabled = !preventionOn;
  });
}

async function saveSettings() {
  const settings = {
    preventionEnabled:        document.getElementById("togglePrevention").checked,
    upgradeHTTPS:             document.getElementById("toggleUpgrade").checked,
    showBlockingPage:         document.getElementById("toggleBlockPage").checked,
    blockInsecureSubResources:document.getElementById("toggleBlockSub").checked,
    notifyOnBlock:            document.getElementById("toggleNotify").checked
  };
  await chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", settings });
  updateTogglesDisabledState(settings.preventionEnabled);
  // Refresh stats to reflect new prevention mode status
  const stats = await chrome.runtime.sendMessage({ type: "GET_STATS" });
  if (stats) updateStats(stats);
}

// Wire up all settings toggles
["togglePrevention","toggleUpgrade","toggleBlockPage","toggleBlockSub","toggleNotify"].forEach(id => {
  document.getElementById(id).addEventListener("change", saveSettings);
});

// ─── Tabs ─────────────────────────────────────────────────────────────────────

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    currentTab = tab.dataset.tab;
    document.getElementById("tabAlerts").style.display   = currentTab === "alerts"   ? "block" : "none";
    document.getElementById("tabSettings").style.display = currentTab === "settings" ? "block" : "none";
    document.getElementById("tabHost").style.display     = currentTab === "host"     ? "block" : "none";
  });
});

// ─── Footer ───────────────────────────────────────────────────────────────────

document.getElementById("btnMarkRead").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "MARK_READ" });
  init();
});

document.getElementById("btnClear").addEventListener("click", async () => {
  if (confirm("Clear all alerts?")) {
    await chrome.runtime.sendMessage({ type: "CLEAR_ALERTS" });
    init();
  }
});

document.getElementById("trustBtn").addEventListener("click", async () => {
  if (!currentHostname) return;
  if (confirm(`Mark "${currentHostname}" as trusted? MITM Detector will stop flagging certificate changes for this host.`)) {
    await chrome.runtime.sendMessage({ type: "TRUST_HOST", hostname: currentHostname });
    init();
  }
});

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  updatePageInfo(tab);

  const [stats, alerts, settings] = await Promise.all([
    chrome.runtime.sendMessage({ type: "GET_STATS" }),
    chrome.runtime.sendMessage({ type: "GET_ALERTS" }),
    chrome.runtime.sendMessage({ type: "GET_SETTINGS" })
  ]);

  if (stats) updateStats(stats);
  renderAlerts(alerts || []);

  if (settings) {
    document.getElementById("togglePrevention").checked = settings.preventionEnabled;
    document.getElementById("toggleUpgrade").checked    = settings.upgradeHTTPS;
    document.getElementById("toggleBlockPage").checked  = settings.showBlockingPage;
    document.getElementById("toggleBlockSub").checked   = settings.blockInsecureSubResources;
    document.getElementById("toggleNotify").checked     = settings.notifyOnBlock;
    updateTogglesDisabledState(settings.preventionEnabled);
  }

  let hostInfo = null;
  let rtcData  = null;
  if (currentHostname) {
    [hostInfo] = await Promise.all([
      chrome.runtime.sendMessage({ type: "GET_HOST_INFO", hostname: currentHostname })
    ]);
    const sessionData = await chrome.storage.session.get(`webrtc_${currentHostname}`);
    rtcData = sessionData[`webrtc_${currentHostname}`] || null;
  }
  renderHostInfo(hostInfo, rtcData, currentHostname);
}

init();
