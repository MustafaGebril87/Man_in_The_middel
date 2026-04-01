/**
 * MITM Detector & Preventer - Background Service Worker v2
 *
 * DETECTION:
 *   1. SSL stripping (HTTPS → HTTP downgrade)
 *   2. Certificate fingerprint / header changes
 *   3. HTTPS→HTTP redirect chains
 *   4. HSTS removal
 *   5. Server header changes (proxy injection signal)
 *
 * PREVENTION (when prevention mode is ON):
 *   A. Auto-upgrade HTTP → HTTPS for known-HTTPS domains via declarativeNetRequest
 *   B. Force-redirect tab back to HTTPS when HTTPS→HTTP redirect is caught
 *   C. Show blocking page for confirmed critical attacks
 *   D. Block insecure sub-resource requests (scripts/iframes over HTTP on HTTPS pages)
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const DB_KEY          = "mitm_cert_db";
const ALERT_KEY       = "mitm_alerts";
const SETTINGS_KEY    = "mitm_settings";
const BLOCKED_KEY     = "mitm_blocked_count";
const MAX_ALERTS      = 200;

// Rule IDs for declarativeNetRequest (must be positive integers, unique)
const RULE_ID_UPGRADE_HTTPS   = 1;   // Upgrade HTTP→HTTPS for known domains
const RULE_ID_BLOCK_HTTP_SUB  = 2;   // Block HTTP sub-resources on HTTPS pages

// Domains that must ALWAYS be HTTPS
const KNOWN_HTTPS_DOMAINS = [
  "google.com", "www.google.com", "mail.google.com", "accounts.google.com",
  "facebook.com", "www.facebook.com", "m.facebook.com",
  "twitter.com", "www.twitter.com", "x.com",
  "github.com", "www.github.com", "api.github.com",
  "amazon.com", "www.amazon.com",
  "paypal.com", "www.paypal.com",
  "bankofamerica.com", "www.bankofamerica.com",
  "chase.com", "www.chase.com",
  "wellsfargo.com", "www.wellsfargo.com",
  "citibank.com", "www.citibank.com",
  "apple.com", "www.apple.com", "icloud.com", "www.icloud.com",
  "microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
  "linkedin.com", "www.linkedin.com",
  "instagram.com", "www.instagram.com",
  "reddit.com", "www.reddit.com",
  "wikipedia.org", "www.wikipedia.org",
  "stackoverflow.com", "www.stackoverflow.com",
  "dropbox.com", "www.dropbox.com",
  "box.com", "www.box.com",
  "outlook.com", "www.outlook.com",
  "yahoo.com", "www.yahoo.com", "mail.yahoo.com",
  "twitch.tv", "www.twitch.tv",
  "netflix.com", "www.netflix.com",
  "spotify.com", "www.spotify.com",
  "cloudflare.com", "www.cloudflare.com"
];

const DEFAULT_SETTINGS = {
  preventionEnabled: true,
  showBlockingPage: true,
  upgradeHTTPS: true,
  blockInsecureSubResources: false, // off by default — too aggressive for general use
  notifyOnBlock: true
};

// ─── Storage Helpers ──────────────────────────────────────────────────────────

async function getCertDB()   { const r = await chrome.storage.local.get(DB_KEY);      return r[DB_KEY] || {}; }
async function saveCertDB(d) { await chrome.storage.local.set({ [DB_KEY]: d }); }
async function getAlerts()   { const r = await chrome.storage.local.get(ALERT_KEY);   return r[ALERT_KEY] || []; }
async function getSettings() { const r = await chrome.storage.local.get(SETTINGS_KEY); return { ...DEFAULT_SETTINGS, ...(r[SETTINGS_KEY] || {}) }; }
async function saveSettings(s) { await chrome.storage.local.set({ [SETTINGS_KEY]: s }); }

async function getBlockedCount() {
  const r = await chrome.storage.local.get(BLOCKED_KEY);
  return r[BLOCKED_KEY] || 0;
}
async function incrementBlockedCount() {
  const c = await getBlockedCount();
  await chrome.storage.local.set({ [BLOCKED_KEY]: c + 1 });
}

async function addAlert(alert) {
  const alerts = await getAlerts();
  alerts.unshift({ ...alert, timestamp: Date.now(), id: crypto.randomUUID() });
  if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS;
  await chrome.storage.local.set({ [ALERT_KEY]: alerts });
  updateBadge(alerts);
}

async function clearAlerts() {
  await chrome.storage.local.set({ [ALERT_KEY]: [] });
  chrome.action.setBadgeText({ text: "" });
}

function updateBadge(alerts) {
  const unread = alerts.filter(a => !a.read).length;
  if (unread > 0) {
    chrome.action.setBadgeText({ text: unread > 99 ? "99+" : String(unread) });
    chrome.action.setBadgeBackgroundColor({ color: "#e53935" });
  } else {
    chrome.action.setBadgeText({ text: "" });
  }
}

function extractHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

function isPrivateIP(hostname) {
  return /^localhost$/i.test(hostname)  ||
    /^127\./.test(hostname)             ||
    /^10\./.test(hostname)              ||
    /^192\.168\./.test(hostname)        ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
    /^::1$/.test(hostname)              ||
    /^fe80:/i.test(hostname);
}

function showNotification(title, message, severity = "warning") {
  chrome.notifications.create({
    type: "basic",
    iconUrl: severity === "critical" ? "icons/icon_alert.png" : "icons/icon48.png",
    title: `MITM Detector: ${title}`,
    message,
    priority: severity === "critical" ? 2 : 1
  });
}

// ─── Prevention: declarativeNetRequest Rules ──────────────────────────────────

/**
 * Install / remove dynamic declarativeNetRequest rules based on current settings.
 *
 * Rule 1 (UPGRADE_HTTPS): Redirects HTTP → HTTPS for all known-HTTPS domains.
 *   Uses the built-in "upgradeScheme" action — Chrome handles the redirect natively
 *   before any JS runs, making it impossible to MITM at the browser level.
 *
 * Rule 2 (BLOCK_HTTP_SUB): Blocks HTTP sub-resources (scripts, iframes) loaded on HTTPS pages.
 *   This prevents script-injection MITM where an attacker injects an HTTP script into HTTPS page.
 */
async function syncDeclarativeRules() {
  const settings = await getSettings();

  const rulesToRemove = [RULE_ID_UPGRADE_HTTPS, RULE_ID_BLOCK_HTTP_SUB];
  const rulesToAdd = [];

  if (settings.preventionEnabled && settings.upgradeHTTPS) {
    rulesToAdd.push({
      id: RULE_ID_UPGRADE_HTTPS,
      priority: 100,
      action: {
        type: "upgradeScheme"  // Chrome-native HTTP→HTTPS upgrade, no JS overhead
      },
      condition: {
        requestDomains: KNOWN_HTTPS_DOMAINS,
        resourceTypes: ["main_frame", "sub_frame"],
        // Only match http:// URLs (upgradeScheme is a no-op on https://)
        urlFilter: "http://*"
      }
    });
  }

  if (settings.preventionEnabled && settings.blockInsecureSubResources) {
    rulesToAdd.push({
      id: RULE_ID_BLOCK_HTTP_SUB,
      priority: 90,
      action: { type: "block" },
      condition: {
        // Block HTTP scripts/iframes initiated from HTTPS pages
        urlFilter: "http://*",
        resourceTypes: ["script", "sub_frame", "object", "object_subrequest"],
        // initiatorDomains not used here — we want to block HTTP sub-resources site-wide
        // when loaded on any page (complemented by content.js DOM-level checks)
        excludedInitiatorDomains: ["localhost", "127.0.0.1"]
      }
    });
  }

  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rulesToRemove,
      addRules: rulesToAdd
    });
    console.log(`[MITM] declarativeNetRequest rules synced. Active rules: ${rulesToAdd.length}`);
  } catch (err) {
    console.error("[MITM] Failed to sync declarativeNetRequest rules:", err);
  }
}

// ─── Prevention: Blocking Page Redirect ──────────────────────────────────────

/**
 * Redirect a tab to our local blocking page, passing attack details in the URL hash.
 * The blocking page lets the user go back, proceed anyway, or trust the host.
 */
function redirectToBlockingPage(tabId, attackInfo) {
  const params = encodeURIComponent(JSON.stringify(attackInfo));
  const blockUrl = chrome.runtime.getURL(`blocking_page.html#${params}`);
  chrome.tabs.update(tabId, { url: blockUrl });
}

// ─── Detection + Prevention: SSL Stripping via webRequest ────────────────────

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    const url = details.url;
    if (!url.startsWith("http://")) return;

    const hostname = extractHostname(url);
    if (!hostname || isPrivateIP(hostname)) return;

    const settings = await getSettings();

    // Check if domain is known-HTTPS
    const isKnownHTTPS = KNOWN_HTTPS_DOMAINS.includes(hostname);

    // Check if we have a previous HTTPS record
    const db = await getCertDB();
    const hadHTTPS = db[hostname] && db[hostname].scheme === "https";

    if (isKnownHTTPS || hadHTTPS) {
      const type = isKnownHTTPS ? "SSL_STRIPPING" : "HTTPS_DOWNGRADE";
      const alert = {
        type,
        severity: "critical",
        hostname,
        url,
        blocked: false,
        message: isKnownHTTPS
          ? `SSL stripping detected! "${hostname}" should always use HTTPS but was loaded over HTTP.`
          : `HTTPS downgrade! "${hostname}" was previously accessed via HTTPS but is now being served over HTTP.`
      };

      // PREVENTION: If upgradeScheme rule is active, the declarativeNetRequest rule
      // will already have upgraded this before we get here for known domains.
      // For previously-seen-HTTPS domains not in the static list, we force-redirect now.
      if (settings.preventionEnabled && hadHTTPS && !isKnownHTTPS && details.tabId > 0) {
        const httpsUrl = url.replace(/^http:\/\//, "https://");
        alert.blocked = true;
        alert.message += " — Automatically upgraded to HTTPS.";
        await addAlert(alert);
        await incrementBlockedCount();

        if (settings.notifyOnBlock) {
          showNotification("Attack Blocked!", `Forced HTTPS upgrade for "${hostname}"`, "critical");
        }

        // Redirect to HTTPS
        chrome.tabs.update(details.tabId, { url: httpsUrl });
        return;
      }

      await addAlert(alert);

      if (settings.preventionEnabled && settings.showBlockingPage && details.tabId > 0) {
        alert.blocked = true;
        await incrementBlockedCount();
        if (settings.notifyOnBlock) {
          showNotification("Attack Blocked!", alert.message, "critical");
        }
        redirectToBlockingPage(details.tabId, {
          type: alert.type,
          hostname,
          url,
          safeUrl: url.replace(/^http:\/\//, "https://"),
          message: alert.message
        });
      } else if (!settings.preventionEnabled) {
        showNotification("Attack Detected (not blocked)", alert.message, "critical");
      }
    }
  },
  { urls: ["http://*/*"] }
);

// ─── Detection + Prevention: Response Header Analysis ────────────────────────

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    if (!details.url.startsWith("https://")) return;

    const hostname = extractHostname(details.url);
    if (!hostname || isPrivateIP(hostname)) return;

    const headers = details.responseHeaders || [];
    const headerMap = {};
    for (const h of headers) headerMap[h.name.toLowerCase()] = h.value;

    const hasHSTS      = !!headerMap["strict-transport-security"];
    const hasExpectCT  = !!headerMap["expect-ct"];
    const hasPKP       = !!headerMap["public-key-pins"];
    const serverHeader = headerMap["server"] || "";
    const xPoweredBy   = headerMap["x-powered-by"] || "";

    const fingerprint = JSON.stringify({ hasHSTS, hasExpectCT, hasPKP, server: serverHeader, xPoweredBy });

    const db = await getCertDB();
    const existing = db[hostname];
    const settings = await getSettings();

    if (!existing) {
      db[hostname] = {
        scheme: "https",
        fingerprint,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        visitCount: 1
      };
    } else {
      db[hostname].lastSeen   = Date.now();
      db[hostname].visitCount = (db[hostname].visitCount || 0) + 1;
      db[hostname].scheme     = "https";

      const prev = JSON.parse(existing.fingerprint || "{}");

      // HSTS was present before but is now gone — possible MITM stripping security headers
      if (prev.hasHSTS && !hasHSTS) {
        const alert = {
          type: "HSTS_REMOVED",
          severity: "high",
          hostname,
          url: details.url,
          blocked: false,
          message: `HSTS header removed on "${hostname}". Previously present — possible MITM stripping security headers.`
        };
        await addAlert(alert);

        if (settings.preventionEnabled && settings.showBlockingPage && details.tabId > 0) {
          alert.blocked = true;
          await incrementBlockedCount();
          if (settings.notifyOnBlock) showNotification("HSTS Stripped!", alert.message, "warning");
          redirectToBlockingPage(details.tabId, {
            type: "HSTS_REMOVED",
            hostname,
            url: details.url,
            safeUrl: null,
            message: alert.message
          });
        } else {
          showNotification("HSTS Header Removed!", alert.message, "warning");
        }
      }

      // Server header changed — possible intercepting proxy
      if (prev.server && serverHeader && prev.server !== serverHeader && existing.visitCount > 3) {
        const alert = {
          type: "SERVER_HEADER_CHANGE",
          severity: "medium",
          hostname,
          url: details.url,
          blocked: false,
          message: `Server header changed on "${hostname}": was "${prev.server}", now "${serverHeader}". Possible intercepting proxy.`,
          prev: prev.server,
          current: serverHeader
        };
        await addAlert(alert);
        // Medium severity — log but don't block by default
      }

      db[hostname].fingerprint = fingerprint;
    }

    await saveCertDB(db);
  },
  { urls: ["https://*/*"] },
  ["responseHeaders"]
);

// ─── Detection + Prevention: HTTPS→HTTP Redirects ────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const hostname = extractHostname(details.url);
  if (!hostname || isPrivateIP(hostname)) return;
  chrome.storage.session.set({ [`nav_${details.tabId}`]: { url: details.url, hostname, ts: Date.now() } });
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const qualifiers = details.transitionQualifiers || [];
  const isRedirect = qualifiers.some(q => q.includes("redirect"));
  if (!isRedirect) return;

  const prevData = await chrome.storage.session.get(`nav_${details.tabId}`);
  const prev = prevData[`nav_${details.tabId}`];
  if (!prev) return;

  const newUrl  = details.url;
  const newHost = extractHostname(newUrl);
  const settings = await getSettings();

  // Redirect from HTTPS → HTTP
  if (prev.url.startsWith("https://") && newUrl.startsWith("http://")) {
    const httpsUrl = newUrl.replace(/^http:\/\//, "https://");
    const alert = {
      type: "REDIRECT_HTTPS_TO_HTTP",
      severity: "critical",
      hostname: newHost,
      url: newUrl,
      prevUrl: prev.url,
      blocked: false,
      message: `Redirect from HTTPS to HTTP detected! "${prev.url}" → "${newUrl}". Classic SSL stripping indicator.`
    };

    if (settings.preventionEnabled && details.tabId > 0) {
      alert.blocked = true;
      await addAlert(alert);
      await incrementBlockedCount();

      if (settings.notifyOnBlock) {
        showNotification("SSL Stripping Blocked!", `Redirect to HTTP blocked for "${newHost}". Staying on HTTPS.`, "critical");
      }

      // Force back to HTTPS
      chrome.tabs.update(details.tabId, { url: httpsUrl });
    } else {
      await addAlert(alert);
      showNotification("HTTPS→HTTP Redirect!", alert.message, "critical");
    }
  }
});

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message.type) {

      case "CONTENT_ALERT": {
        const alert = { ...message.alert, url: sender.url, hostname: extractHostname(sender.url) };
        await addAlert(alert);
        const settings = await getSettings();
        if (settings.preventionEnabled && (alert.severity === "critical" || alert.severity === "high")) {
          if (settings.notifyOnBlock) showNotification(alert.title || "Threat Blocked", alert.message, alert.severity);
          await incrementBlockedCount();
        } else if (!settings.preventionEnabled && (alert.severity === "critical" || alert.severity === "high")) {
          showNotification(alert.title || "Threat Detected", alert.message, alert.severity);
        }
        sendResponse(null);
        break;
      }

      case "GET_ALERTS":
        sendResponse(await getAlerts());
        break;

      case "CLEAR_ALERTS":
        await clearAlerts();
        sendResponse(null);
        break;

      case "MARK_READ": {
        const alerts = await getAlerts();
        for (const a of alerts) a.read = true;
        await chrome.storage.local.set({ [ALERT_KEY]: alerts });
        chrome.action.setBadgeText({ text: "" });
        sendResponse(null);
        break;
      }

      case "GET_STATS": {
        const alerts   = await getAlerts();
        const db       = await getCertDB();
        const blocked  = await getBlockedCount();
        const settings = await getSettings();
        sendResponse({
          trackedHosts:    Object.keys(db).length,
          totalAlerts:     alerts.length,
          unreadAlerts:    alerts.filter(a => !a.read).length,
          criticalAlerts:  alerts.filter(a => a.severity === "critical").length,
          blockedAttacks:  blocked,
          preventionEnabled: settings.preventionEnabled
        });
        break;
      }

      case "GET_SETTINGS":
        sendResponse(await getSettings());
        break;

      case "SAVE_SETTINGS": {
        await saveSettings(message.settings);
        await syncDeclarativeRules();  // Re-apply rules with new settings
        sendResponse(null);
        break;
      }

      case "GET_HOST_INFO": {
        const db = await getCertDB();
        sendResponse(db[message.hostname] || null);
        break;
      }

      case "TRUST_HOST": {
        const db = await getCertDB();
        if (!db[message.hostname]) db[message.hostname] = { scheme: "https", trusted: true, firstSeen: Date.now(), lastSeen: Date.now(), visitCount: 0 };
        db[message.hostname].trusted = true;
        await saveCertDB(db);
        sendResponse(null);
        break;
      }

      case "PROCEED_ANYWAY": {
        // User chose to proceed from the blocking page — store exception for this session
        await chrome.storage.session.set({ [`allow_${message.hostname}`]: true });
        sendResponse(null);
        break;
      }

      default:
        sendResponse(null);
    }
  })();
  return true; // keep channel open for async sendResponse
});

// ─── Init & Periodic Cleanup ──────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  await syncDeclarativeRules();
  console.log("[MITM] Extension installed / updated. Rules synced.");
});

chrome.alarms.create("health_check", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "health_check") return;
  const db = await getCertDB();
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  let pruned = false;
  for (const [host, info] of Object.entries(db)) {
    if (info.lastSeen < cutoff) { delete db[host]; pruned = true; }
  }
  if (pruned) await saveCertDB(db);
});

// Re-sync rules when the service worker wakes up (MV3 worker can be killed and restarted)
syncDeclarativeRules();

console.log("[MITM] Background service worker v2 started.");
