/**
 * MITM Detector - Content Script v2
 * Detects AND prevents page-level MITM signals:
 *   Detection:  Mixed content, SSL stripping signals, suspicious iframes, WebRTC leaks
 *   Prevention: Block insecure script execution, intercept insecure form submissions,
 *               intercept createElement to catch runtime script injections
 */

(function () {
  "use strict";

  if (window.self !== window.top) return; // top frame only

  const isHTTPS  = location.protocol === "https:";
  const hostname = location.hostname;

  const HIGH_VALUE_DOMAINS = [
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "amazon.com", "google.com", "facebook.com",
    "apple.com", "icloud.com", "microsoft.com", "github.com",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
    "gmail.com", "outlook.com", "yahoo.com", "x.com"
  ];

  function sendAlert(alert) {
    chrome.runtime.sendMessage({ type: "CONTENT_ALERT", alert });
  }

  function isInsecureUrl(url) {
    return typeof url === "string" && url.startsWith("http://");
  }

  // ─── Get prevention mode from background ─────────────────────────────────────
  let preventionEnabled = true; // default optimistic — will be updated async
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (settings) => {
    if (settings) preventionEnabled = settings.preventionEnabled;
  });

  // ─── 1. Intercept createElement to block insecure script injection ────────────
  // Override document.createElement BEFORE any page scripts run (document_start).
  // This catches MITM-injected scripts that are added programmatically.
  if (isHTTPS) {
    const _createElement = Document.prototype.createElement;
    Document.prototype.createElement = function (tagName, options) {
      const el = _createElement.call(this, tagName, options);

      if (typeof tagName === "string" && tagName.toLowerCase() === "script") {
        // Intercept the `src` setter — block it if the src is http://
        const _srcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src");

        let _pendingSrc = "";
        Object.defineProperty(el, "src", {
          get() {
            return _srcDescriptor ? _srcDescriptor.get.call(this) : _pendingSrc;
          },
          set(val) {
            if (isInsecureUrl(val)) {
              if (preventionEnabled) {
                sendAlert({
                  type: "BLOCKED_INSECURE_SCRIPT",
                  severity: "high",
                  title: "Insecure Script Blocked",
                  message: `Blocked attempt to load an HTTP script on HTTPS page "${hostname}": ${val.substring(0, 150)}`,
                  src: val.substring(0, 300),
                  blocked: true
                });
                // Do NOT set the src — leave it empty, neutering the script
                return;
              } else {
                sendAlert({
                  type: "INSECURE_SCRIPT",
                  severity: "high",
                  title: "Insecure Script Source",
                  message: `HTTP script loaded on HTTPS page "${hostname}": ${val.substring(0, 150)}`,
                  src: val.substring(0, 300)
                });
              }
            }
            if (_srcDescriptor) _srcDescriptor.set.call(this, val);
            else _pendingSrc = val;
          },
          configurable: true
        });
      }
      return el;
    };
  }

  // ─── 2. MutationObserver: monitor dynamically added nodes ────────────────────
  if (isHTTPS) {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          handleAddedNode(node);
        }
      }
    });

    function handleAddedNode(el) {
      const tag = el.tagName ? el.tagName.toLowerCase() : "";

      // Block or flag insecure script src
      if (tag === "script") {
        const src = el.getAttribute("src") || "";
        if (isInsecureUrl(src)) {
          if (preventionEnabled) {
            el.removeAttribute("src");  // Neuter the script
            el.textContent = "";        // Clear any inline content added alongside
            sendAlert({
              type: "BLOCKED_INSECURE_SCRIPT",
              severity: "high",
              title: "Insecure Script Blocked",
              message: `Blocked HTTP script injection on "${hostname}": ${src.substring(0, 150)}`,
              src: src.substring(0, 300),
              blocked: true
            });
          } else {
            sendAlert({
              type: "INSECURE_SCRIPT",
              severity: "high",
              title: "Insecure Script Source",
              message: `HTTP script loaded on HTTPS page "${hostname}": ${src.substring(0, 150)}`,
              src: src.substring(0, 300)
            });
          }
        }

        // Detect suspicious large inline scripts accessing sensitive APIs
        if (!src) {
          const code = el.textContent || "";
          const isSuspicious =
            code.length > 1500 && (
              code.includes("document.cookie") ||
              code.includes("localStorage")    ||
              code.includes("sessionStorage")  ||
              code.includes("XMLHttpRequest")  ||
              code.includes("fetch(")          ||
              code.includes("WebSocket")
            );
          if (isSuspicious) {
            sendAlert({
              type: "SUSPICIOUS_INLINE_SCRIPT",
              severity: "medium",
              title: "Suspicious Inline Script",
              message: `Large inline script accessing sensitive APIs was dynamically injected on "${hostname}". Possible MITM content injection.`,
              preview: code.substring(0, 200)
            });
          }
        }
      }

      // Flag insecure iframes
      if (tag === "iframe") {
        const frameSrc = el.getAttribute("src") || "";
        if (isInsecureUrl(frameSrc)) {
          if (preventionEnabled) {
            el.setAttribute("src", "about:blank");
            sendAlert({
              type: "BLOCKED_INSECURE_IFRAME",
              severity: "high",
              title: "Insecure Iframe Blocked",
              message: `Blocked HTTP iframe on HTTPS page "${hostname}": ${frameSrc.substring(0, 150)}`,
              blocked: true
            });
          } else {
            sendAlert({
              type: "INSECURE_IFRAME",
              severity: "high",
              title: "Insecure Iframe",
              message: `HTTP iframe on HTTPS page "${hostname}": ${frameSrc.substring(0, 150)}`
            });
          }
        }
      }

      // Check other elements for insecure attributes
      const insecureAttrs = ["src", "href", "action", "data"];
      for (const attr of insecureAttrs) {
        const val = el.getAttribute?.(attr);
        if (val && isInsecureUrl(val) && tag !== "script" && tag !== "iframe") {
          sendAlert({
            type: "MIXED_CONTENT",
            severity: "medium",
            title: "Mixed Content",
            message: `HTTPS page "${hostname}" loading insecure <${tag.toUpperCase()} ${attr}>: ${val.substring(0, 100)}`
          });
        }
      }
    }

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["src", "href", "action", "data"]
    });

    // Scan existing DOM once it's ready
    document.addEventListener("DOMContentLoaded", () => {
      document.querySelectorAll("script[src], iframe[src], [src], [href], [action]").forEach(handleAddedNode);
    });
  }

  // ─── 3. SSL Stripping signal: high-value domain over HTTP ────────────────────
  if (!isHTTPS) {
    const matchedDomain = HIGH_VALUE_DOMAINS.find(d =>
      hostname === d || hostname.endsWith("." + d)
    );
    if (matchedDomain) {
      sendAlert({
        type: "HIGH_VALUE_HTTP",
        severity: "critical",
        title: "High-Value Site Over HTTP",
        message: `"${hostname}" is a high-value domain being accessed over plain HTTP. This is a strong SSL stripping indicator.`
      });
    }
  }

  // ─── 4. Intercept insecure form submissions ───────────────────────────────────
  // Prevent login/payment forms from submitting over HTTP
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!form || form.tagName !== "FORM") return;

    const action = form.action || location.href;
    const isInsecureSubmit = action.startsWith("http://") && isHTTPS;
    const isInsecurePage   = !isHTTPS && HIGH_VALUE_DOMAINS.some(d =>
      hostname === d || hostname.endsWith("." + d)
    );

    const hasPasswordField = !!form.querySelector('input[type="password"]');
    const hasCardField     = !!form.querySelector('[name*="card"], [name*="cvv"], [name*="ccv"], [autocomplete*="cc"]');
    const isSensitiveForm  = hasPasswordField || hasCardField;

    if (isInsecureSubmit && isSensitiveForm && preventionEnabled) {
      event.preventDefault();
      event.stopImmediatePropagation();
      sendAlert({
        type: "BLOCKED_INSECURE_FORM",
        severity: "critical",
        title: "Insecure Form Submission Blocked",
        message: `Blocked a sensitive form (${hasPasswordField ? "password" : "payment"} fields) from submitting over HTTP on "${hostname}". The form action was: ${action.substring(0, 100)}`,
        blocked: true
      });

      // Show inline warning to user
      showInlineWarning(form,
        "MITM Detector blocked this form submission because it would send your credentials over an insecure HTTP connection. This may be a phishing or MITM attack."
      );
      return;
    }

    if (isInsecurePage && isSensitiveForm && preventionEnabled) {
      event.preventDefault();
      event.stopImmediatePropagation();
      sendAlert({
        type: "BLOCKED_CREDENTIALS_OVER_HTTP",
        severity: "critical",
        title: "Credential Submission Blocked",
        message: `Blocked ${hasPasswordField ? "login" : "payment"} form submission on high-value HTTP site "${hostname}". This is likely SSL stripping.`,
        blocked: true
      });
      showInlineWarning(form,
        `MITM Detector blocked this form: "${hostname}" should be using HTTPS. Your credentials were not sent.`
      );
    }
  }, true); // capture phase — runs before page's own handlers

  function showInlineWarning(nearElement, message) {
    if (document.getElementById("mitm-detector-warning")) return; // only once

    const banner = document.createElement("div");
    banner.id = "mitm-detector-warning";
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: #7f1d1d; color: #fecaca; padding: 14px 20px;
      font: 600 13px/1.4 -apple-system, sans-serif;
      display: flex; align-items: center; gap: 12px;
      border-bottom: 2px solid #ef4444; box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    `;
    banner.innerHTML = `
      <span style="font-size:20px">🛡</span>
      <span style="flex:1">${message}</span>
      <button onclick="this.parentElement.remove()" style="
        background:transparent; border:1px solid #fca5a5; color:#fecaca;
        padding:4px 10px; border-radius:4px; cursor:pointer; font-size:12px;
      ">Dismiss</button>
    `;
    document.documentElement.appendChild(banner);

    setTimeout(() => banner.remove(), 15000);
  }

  // ─── 5. WebRTC IP Leak Detection ─────────────────────────────────────────────
  function detectWebRTCLeak() {
    if (typeof RTCPeerConnection === "undefined") return;
    const rtc  = new RTCPeerConnection({ iceServers: [] });
    const ips  = new Set();
    rtc.createDataChannel("");
    rtc.createOffer().then(o => rtc.setLocalDescription(o)).catch(() => {});
    rtc.onicecandidate = (e) => {
      if (!e?.candidate?.candidate) { rtc.close(); return; }
      const match = e.candidate.candidate.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (match) {
        ips.add(match[1]);
        chrome.storage.session.set({ [`webrtc_${hostname}`]: { ips: [...ips], ts: Date.now() } });
      }
    };
    setTimeout(() => rtc.close(), 3000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", detectWebRTCLeak);
  } else {
    detectWebRTCLeak();
  }

  // ─── 6. Cross-origin iframe detection on sensitive pages ─────────────────────
  window.addEventListener("load", () => {
    const isAuthPage = /login|signin|auth|checkout|payment|account|secure/i.test(location.pathname);
    if (!isAuthPage) return;

    document.querySelectorAll("iframe").forEach(frame => {
      const src = frame.src || "";
      if (!src || src.startsWith("about:") || src.startsWith("javascript:")) return;
      try {
        const frameHost = new URL(src).hostname;
        if (frameHost !== hostname) {
          sendAlert({
            type: "SUSPICIOUS_IFRAME",
            severity: "high",
            title: "Cross-Origin Iframe on Sensitive Page",
            message: `Cross-origin iframe from "${frameHost}" detected on sensitive page "${hostname}${location.pathname}". Possible clickjacking or MITM injection.`,
            frameSrc: src.substring(0, 200)
          });
        }
      } catch (_) {}
    });
  });

})();
