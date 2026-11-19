/**
 * DevGuard Static Site HTML Snippet Guard
 *
 * Single-file drop-in script for static sites, Jamstack, Jekyll, Astro, Hugo, and Webflow exports.
 * Features:
 * - Ed25519 asymmetric signature verification (WebCrypto / Node / fallback)
 * - Anti-replay and anti-staleness timestamp validation
 * - Domain allowlist verification (wildcards, ports, localhost)
 * - Tamper-resistant full-viewport lock overlay guarded by MutationObserver
 * - Non-intrusive warning top banner
 * - Default fail-safe open on network error
 * - Zero external runtime dependencies (<15KB bundle footprint)
 *
 * @package @devguard-uk/static-snippet-guard
 * @version 1.0.0
 * @license Apache-2.0
 */

(function (global) {
  'use strict';

  // =========================================================================
  // 1. Domain Matcher Utilities
  // =========================================================================

  /**
   * Normalizes a host or domain string:
   * Strips whitespace, converts to lowercase, removes ports, IPv6 brackets, trailing dot,
   * and rejects header/URI injection characters.
   */
  function normalizeHost(rawHost) {
    if (rawHost == null) return '';
    let str = String(rawHost).trim().toLowerCase();
    if (!str) return '';

    // Reject characters used in injection or spoofing
    if (/[\r\n\0/\s\\?#@]/.test(str)) {
      return '';
    }

    // Handle IPv6 bracket notation [::1]:8080
    if (str.startsWith('[')) {
      const endBracket = str.indexOf(']');
      if (endBracket !== -1) {
        return str.slice(1, endBracket);
      }
    }

    // Strip port if present
    const colonIdx = str.indexOf(':');
    if (colonIdx !== -1) {
      str = str.slice(0, colonIdx);
    }

    // Strip trailing FQDN dot
    if (str.endsWith('.')) {
      str = str.slice(0, -1);
    }

    return str;
  }

  /**
   * Checks whether host matches allowedDomains list.
   * Empty or null list means domain lock is disabled (returns true).
   */
  function isDomainAllowed(host, allowedDomains) {
    if (!allowedDomains) return true;

    let list = [];
    if (Array.isArray(allowedDomains)) {
      list = allowedDomains;
    } else if (typeof allowedDomains === 'string') {
      list = allowedDomains.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    }

    if (list.length === 0) return true;

    const target = normalizeHost(host);
    if (!target) return false;

    for (let i = 0; i < list.length; i++) {
      const rawPattern = list[i];
      if (!rawPattern || typeof rawPattern !== 'string') continue;
      const pat = rawPattern.trim().toLowerCase();
      if (!pat) continue;

      if (pat === '*') return true;

      // Wildcard matching e.g. *.example.com
      if (pat.startsWith('*.')) {
        const baseDomain = normalizeHost(pat.slice(2));
        if (!baseDomain) continue;

        // Exact match with apex domain
        if (target === baseDomain) return true;

        // Subdomain match (must strictly have a dot separator)
        if (target.endsWith('.' + baseDomain)) {
          return true;
        }
        continue;
      }

      // Exact match
      const normalizedPattern = normalizeHost(pat);
      if (normalizedPattern && target === normalizedPattern) {
        return true;
      }
    }

    return false;
  }

  // =========================================================================
  // 2. Cryptographic Canonical Serialization & Decoding
  // =========================================================================

  /**
   * Computes deterministic canonical string for public status payload.
   */
  function computeStatusCanonicalString(opts) {
    if (!opts) return '';
    const projectId = opts.projectId || opts.id || '';
    const status = opts.status || '';
    const timestamp = opts.timestamp != null ? opts.timestamp : '';

    let domainsStr = '';
    if (Array.isArray(opts.allowedDomains)) {
      domainsStr = opts.allowedDomains
        .map(function (d) { return String(d).trim().toLowerCase(); })
        .sort()
        .join(',');
    } else if (typeof opts.allowedDomains === 'string') {
      domainsStr = opts.allowedDomains.trim().toLowerCase();
    }

    const autolockState = opts.autolockState || '';
    return `${projectId}:${status}:${timestamp}:${domainsStr}:${autolockState}`;
  }

  /**
   * Converts Hex string to Uint8Array.
   */
  function hexToUint8Array(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const len = clean.length;
    const out = new Uint8Array(len >> 1);
    for (let i = 0; i < len; i += 2) {
      out[i >> 1] = parseInt(clean.substring(i, i + 2), 16);
    }
    return out;
  }

  /**
   * Converts Base64 string to Uint8Array.
   */
  function base64ToUint8Array(b64) {
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      return new Uint8Array(Buffer.from(b64, 'base64'));
    }
    if (typeof atob === 'function') {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        out[i] = bin.charCodeAt(i);
      }
      return out;
    }
    throw new Error('Base64 decoding not supported in this environment');
  }

  /**
   * Decodes an Ed25519 public key (hex, PEM, base64, or Uint8Array) to raw 32-byte Uint8Array.
   */
  function decodePublicKey(pubKeyInput) {
    if (!pubKeyInput) return null;

    if (pubKeyInput instanceof Uint8Array) {
      if (pubKeyInput.length === 32) return pubKeyInput;
      if (pubKeyInput.length === 44) return pubKeyInput.slice(12); // SPKI DER
      return pubKeyInput;
    }

    if (typeof pubKeyInput !== 'string') return null;
    const str = pubKeyInput.trim();

    // Check PEM format
    if (str.includes('BEGIN PUBLIC KEY')) {
      const b64 = str
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s+/g, '');
      const bytes = base64ToUint8Array(b64);
      if (bytes.length === 44) {
        return bytes.slice(12); // Skip 12-byte SPKI header
      }
      return bytes.slice(-32);
    }

    // Check Hex (64 hex characters)
    if (/^[0-9a-fA-F]{64}$/.test(str)) {
      return hexToUint8Array(str);
    }

    // Try Base64
    try {
      const bytes = base64ToUint8Array(str);
      if (bytes.length === 32) return bytes;
      if (bytes.length === 44) return bytes.slice(12);
    } catch (_) {}

    return null;
  }

  /**
   * Decodes an Ed25519 signature (hex, base64, or Uint8Array) to raw 64-byte Uint8Array.
   */
  function decodeSignature(sigInput) {
    if (!sigInput) return null;
    if (sigInput instanceof Uint8Array) {
      return sigInput.length === 64 ? sigInput : null;
    }
    if (typeof sigInput !== 'string') return null;
    const str = sigInput.trim();

    // Check 128 hex chars
    if (/^[0-9a-fA-F]{128}$/.test(str)) {
      return hexToUint8Array(str);
    }

    // Try base64 (88 chars)
    try {
      const bytes = base64ToUint8Array(str);
      if (bytes.length === 64) return bytes;
    } catch (_) {}

    return null;
  }

  /**
   * Converts string or Uint8Array to message Uint8Array.
   */
  function toMessageBytes(msg) {
    if (msg instanceof Uint8Array) return msg;
    if (typeof msg === 'string') {
      if (typeof TextEncoder !== 'undefined') {
        return new TextEncoder().encode(msg);
      }
      if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
        return new Uint8Array(Buffer.from(msg, 'utf8'));
      }
      const out = new Uint8Array(msg.length);
      for (let i = 0; i < msg.length; i++) {
        out[i] = msg.charCodeAt(i) & 0xff;
      }
      return out;
    }
    return new Uint8Array(0);
  }

  // =========================================================================
  // 3. Ed25519 Verification Engine
  // =========================================================================

  /**
   * Verifies an Ed25519 signature against message and developer public key.
   * Multi-strategy:
   * 1. Browser WebCrypto (`crypto.subtle.verify`)
   * 2. Node.js built-in `crypto.verify` (for SSR / Node test harnesses)
   *
   * @param {string|Uint8Array} publicKey Developer Ed25519 public key
   * @param {string|Uint8Array} signature Signature bytes or hex
   * @param {string|Uint8Array} message Canonical signable message
   * @returns {Promise<boolean>}
   */
  async function verifyEd25519(publicKey, signature, message) {
    const rawPub = decodePublicKey(publicKey);
    const rawSig = decodeSignature(signature);
    const msgBytes = toMessageBytes(message);

    if (!rawPub || rawPub.length !== 32) return false;
    if (!rawSig || rawSig.length !== 64) return false;

    // Strategy 1: Browser WebCrypto Subtle (Chrome 113+, Safari 17+, Firefox 129+, Node 19+)
    const subtle = typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null;
    if (subtle && typeof subtle.importKey === 'function') {
      try {
        const cryptoKey = await subtle.importKey(
          'raw',
          rawPub,
          { name: 'Ed25519' },
          false,
          ['verify']
        );
        return await subtle.verify({ name: 'Ed25519' }, cryptoKey, rawSig, msgBytes);
      } catch (err) {
        // Subtle may throw if Ed25519 algorithm is disabled or in older browser engine
      }
    }

    // Strategy 2: Node.js standard crypto (Node.js >= 16)
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const nodeCrypto = require('crypto');
        const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
        const spkiDer = Buffer.concat([spkiPrefix, Buffer.from(rawPub)]);
        const pubKeyObj = nodeCrypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
        return nodeCrypto.verify(null, Buffer.from(msgBytes), pubKeyObj, Buffer.from(rawSig));
      } catch (err) {
        // Fall through
      }
    }

    return false;
  }

  // =========================================================================
  // 4. DOM Presentation & Anti-Tamper Observer
  // =========================================================================

  let activeMutationObserver = null;
  let activeKeydownListener = null;

  /**
   * Escapes HTML strings to prevent XSS in banner and overlay text.
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Removes any active warning banner or lock overlay and restores scroll.
   */
  function cleanupDomInterventions() {
    if (activeMutationObserver) {
      activeMutationObserver.disconnect();
      activeMutationObserver = null;
    }
    if (activeKeydownListener && typeof window !== 'undefined') {
      window.removeEventListener('keydown', activeKeydownListener, true);
      activeKeydownListener = null;
    }

    if (typeof document === 'undefined') return;

    const overlay = document.getElementById('devguard-lock-overlay');
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }

    const banner = document.getElementById('devguard-warning-banner');
    if (banner && banner.parentNode) {
      banner.parentNode.removeChild(banner);
    }

    if (document.body && document.body.style) {
      if (typeof document.body.style.removeProperty === 'function') {
        document.body.style.removeProperty('overflow');
        document.body.style.removeProperty('pointer-events');
        document.body.style.removeProperty('padding-top');
      } else {
        delete document.body.style.overflow;
        delete document.body.style.pointerEvents;
        delete document.body.style.paddingTop;
      }
    }
    if (document.documentElement && document.documentElement.style) {
      if (typeof document.documentElement.style.removeProperty === 'function') {
        document.documentElement.style.removeProperty('overflow');
      } else {
        delete document.documentElement.style.overflow;
      }
    }
  }

  /**
   * Injects non-intrusive sticky warning banner at top of body.
   */
  function renderWarningBanner(opts) {
    if (typeof document === 'undefined' || !document.body) return;

    cleanupDomInterventions();
    opts = opts || {};
    const title = escapeHtml(opts.title || 'DevGuard Notice');
    const message = escapeHtml(opts.message || 'Payment notice active for this website.');
    const contactEmail = opts.contactEmail ? escapeHtml(opts.contactEmail) : '';
    const contactWhatsapp = opts.contactWhatsapp ? escapeHtml(opts.contactWhatsapp.replace(/[^\d+]/g, '')) : '';

    const banner = document.createElement('div');
    banner.id = 'devguard-warning-banner';
    banner.setAttribute('role', 'alert');
    banner.style.cssText =
      'position:fixed!important;top:0!important;left:0!important;right:0!important;width:100%!important;z-index:2147483640!important;background:#1e1b18!important;border-bottom:2px solid #f59e0b!important;color:#fef3c7!important;padding:12px 20px!important;box-shadow:0 4px 20px rgba(0,0,0,0.45)!important;font-family:-apple-system,BlinkMacSystemFont,sans-serif!important;font-size:14px!important;display:flex!important;align-items:center!important;justify-content:space-between!important;flex-wrap:wrap!important;gap:12px!important;box-sizing:border-box!important;';

    let actionsHtml = '';
    if (contactEmail) {
      actionsHtml += `<a href="mailto:${contactEmail}" style="background:#f59e0b;color:#111;padding:6px 14px;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px;">Contact Support</a>`;
    } else if (contactWhatsapp) {
      actionsHtml += `<a href="https://wa.me/${contactWhatsapp}" target="_blank" rel="noopener" style="background:#25d366;color:#111;padding:6px 14px;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px;">WhatsApp</a>`;
    }

    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-size:18px;">⚠️</span>
        <div><strong style="color:#fbbf24;">${title}:</strong> <span style="margin-left:6px;">${message}</span></div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        ${actionsHtml}
        <button id="devguard-dismiss-banner" aria-label="Dismiss banner" style="background:transparent;border:none;color:#9ca3af;font-size:18px;cursor:pointer;padding:2px 8px;">✕</button>
      </div>
    `;

    document.body.insertBefore(banner, document.body.firstChild);
    document.body.style.paddingTop = '60px';

    const dismissBtn = banner.querySelector('#devguard-dismiss-banner');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', function () {
        cleanupDomInterventions();
      });
    }
  }

  /**
   * Mounts unclosable full-viewport lock overlay guarded by MutationObserver.
   */
  function renderLockOverlay(opts) {
    if (typeof document === 'undefined' || !document.body) return;

    cleanupDomInterventions();
    opts = opts || {};
    const title = escapeHtml(opts.title || 'Application Access Suspended');
    const message = escapeHtml(
      opts.message ||
        'This static website is currently suspended due to an administrative or milestone payment hold.'
    );
    const contactEmail = opts.contactEmail ? escapeHtml(opts.contactEmail) : '';
    const contactWhatsapp = opts.contactWhatsapp ? escapeHtml(opts.contactWhatsapp.replace(/[^\d+]/g, '')) : '';
    const contactPhone = opts.contactPhone ? escapeHtml(opts.contactPhone) : '';
    const dueAt = opts.dueAt || opts.paymentDueAt;
    const autolockReason = opts.lockReason || opts.autolockState;

    function buildOverlayElement() {
      const overlay = document.createElement('div');
      overlay.id = 'devguard-lock-overlay';
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      overlay.style.cssText =
        'position:fixed!important;top:0!important;left:0!important;width:100vw!important;height:100vh!important;max-width:100vw!important;max-height:100vh!important;z-index:2147483647!important;background:rgba(9,13,22,0.98)!important;backdrop-filter:blur(14px)!important;-webkit-backdrop-filter:blur(14px)!important;display:flex!important;align-items:center!important;justify-content:center!important;margin:0!important;padding:24px!important;box-sizing:border-box!important;color:#f8fafc!important;font-family:-apple-system,BlinkMacSystemFont,sans-serif!important;pointer-events:auto!important;user-select:none!important;';

      let contactButtonsHtml = '';
      if (contactEmail) {
        contactButtonsHtml += `<a href="mailto:${contactEmail}" style="background:#0284c7;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;display:inline-block;">Email Support</a>`;
      }
      if (contactWhatsapp) {
        contactButtonsHtml += `<a href="https://wa.me/${contactWhatsapp}" target="_blank" rel="noopener" style="background:#25d366;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;display:inline-block;">WhatsApp</a>`;
      }
      if (contactPhone) {
        contactButtonsHtml += `<a href="tel:${contactPhone}" style="background:#334155;color:#cbd5e1;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;display:inline-block;">Call Support</a>`;
      }

      let metaInfoHtml = '';
      if (dueAt) {
        metaInfoHtml += `<div style="font-size:12px;color:#94a3b8;margin-top:8px;">Milestone Due Date: <strong>${escapeHtml(String(dueAt))}</strong></div>`;
      }
      if (autolockReason) {
        metaInfoHtml += `<div style="font-size:12px;color:#f87171;margin-top:4px;">Reason: ${escapeHtml(String(autolockReason))}</div>`;
      }

      overlay.innerHTML = `
        <div style="background:#111827;border:1px solid #1f2937;border-radius:16px;padding:36px 32px;max-width:540px;width:100%;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,0.7);box-sizing:border-box;">
          <div style="width:64px;height:64px;margin:0 auto 20px;border-radius:50%;background:rgba(239,68,68,0.12);display:flex;align-items:center;justify-content:center;font-size:30px;border:1px solid rgba(239,68,68,0.3);">
            🔒
          </div>
          <div style="display:inline-block;padding:4px 12px;border-radius:9999px;background:rgba(239,68,68,0.15);color:#f87171;font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:12px;">
            Service Suspended
          </div>
          <h1 style="font-size:22px;font-weight:700;margin:0 0 12px;color:#f8fafc;line-height:1.3;">
            ${title}
          </h1>
          <p style="font-size:14px;color:#cbd5e1;line-height:1.6;margin:0 0 20px;">
            ${message}
          </p>
          ${metaInfoHtml}
          <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:24px;">
            ${contactButtonsHtml}
          </div>
          <div style="margin-top:28px;padding-top:16px;border-top:1px solid #1e293b;font-size:11px;color:#64748b;">
            Protected by DevGuard Web Security • Cryptographically Attested
          </div>
        </div>
      `;

      return overlay;
    }

    function mountLock() {
      let overlay = document.getElementById('devguard-lock-overlay');
      if (!overlay) {
        overlay = buildOverlayElement();
        document.body.appendChild(overlay);
      }

      // Freeze scrolling and body interaction
      document.body.style.setProperty('overflow', 'hidden', 'important');
      document.documentElement.style.setProperty('overflow', 'hidden', 'important');
    }

    mountLock();

    // Prevent ESC or keyboard dismiss
    if (typeof window !== 'undefined') {
      activeKeydownListener = function (e) {
        if (e.key === 'Escape' || e.keyCode === 27) {
          e.preventDefault();
          e.stopPropagation();
        }
      };
      window.addEventListener('keydown', activeKeydownListener, true);
    }

    // Install anti-tamper MutationObserver
    if (typeof MutationObserver !== 'undefined') {
      activeMutationObserver = new MutationObserver(function () {
        const overlay = document.getElementById('devguard-lock-overlay');
        if (!overlay || !document.body.contains(overlay)) {
          // DevTools removed the node: re-mount immediately
          mountLock();
          return;
        }

        // Check if DevTools hid the node via CSS
        if (typeof window !== 'undefined' && window.getComputedStyle) {
          const style = window.getComputedStyle(overlay);
          if (
            style.display === 'none' ||
            style.visibility === 'hidden' ||
            parseFloat(style.opacity) < 0.1 ||
            overlay.hasAttribute('hidden')
          ) {
            overlay.removeAttribute('hidden');
            overlay.style.setProperty('display', 'flex', 'important');
            overlay.style.setProperty('visibility', 'visible', 'important');
            overlay.style.setProperty('opacity', '1', 'important');
          }
        }

        if (document.body.style.overflow !== 'hidden') {
          document.body.style.setProperty('overflow', 'hidden', 'important');
        }
      });

      activeMutationObserver.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
      });
    }
  }

  // =========================================================================
  // 5. Script Configuration Extractor
  // =========================================================================

  /**
   * Finds the active snippet <script> element and parses configuration attributes.
   */
  function extractScriptConfig(doc) {
    if (!doc) return null;

    let script = doc.currentScript;
    if (!script) {
      script = doc.querySelector('script[data-project-id]');
    }
    if (!script) {
      script = doc.querySelector('script[src*="devguard-snippet"]');
    }
    if (!script) return null;

    const projectId = script.getAttribute('data-project-id');
    const publicKey = script.getAttribute('data-public-key');
    let apiUrl = script.getAttribute('data-api-url') || 'https://api.devguard.uk';
    apiUrl = apiUrl.replace(/\/+$/, '');
    const failSafe = (script.getAttribute('data-fail-safe') || 'open').toLowerCase();
    const maxSkew = parseInt(script.getAttribute('data-max-skew') || '300', 10);
    const refreshInterval = parseInt(script.getAttribute('data-refresh-interval') || '0', 10);

    return {
      projectId: projectId ? projectId.trim() : '',
      publicKey: publicKey ? publicKey.trim() : '',
      apiUrl,
      failSafe,
      maxSkew,
      refreshInterval,
      element: script,
    };
  }

  // =========================================================================
  // 6. Runtime Verification Execution
  // =========================================================================

  /**
   * Executes status check against DevGuard API.
   */
  async function checkStatus(config) {
    if (!config || !config.projectId) {
      console.warn('[DevGuard] Missing required data-project-id attribute on snippet script.');
      return { ok: false, error: 'MISSING_PROJECT_ID' };
    }

    const { projectId, publicKey, apiUrl, failSafe, maxSkew } = config;
    const currentHost = typeof window !== 'undefined' && window.location ? window.location.hostname : '';

    try {
      const endpoint = `${apiUrl}/api/v1/projects/${encodeURIComponent(projectId)}/public-status`;
      const res = await fetch(endpoint, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });

      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}`);
      }

      const payload = await res.json();
      if (!payload || !payload.ok) {
        throw new Error(payload?.error || 'Invalid API status response');
      }

      // 1. Replay / Anti-staleness verification
      if (payload.timestamp != null && maxSkew > 0) {
        const clientNowSec = Math.floor(Date.now() / 1000);
        const skew = Math.abs(clientNowSec - payload.timestamp);
        if (skew > maxSkew) {
          throw new Error(`STATUS_STALE: Skew of ${skew}s exceeds tolerance of ${maxSkew}s`);
        }
      }

      // 2. Cryptographic Ed25519 signature verification
      if (publicKey) {
        if (!payload.ed25519Signature) {
          throw new Error('STATUS_UNSIGNED: Expected ed25519Signature from API but received null');
        }

        const canonical = computeStatusCanonicalString({
          projectId,
          status: payload.status,
          timestamp: payload.timestamp,
          allowedDomains: payload.allowedDomains,
          autolockState: payload.autolockState,
        });

        const isValid = await verifyEd25519(publicKey, payload.ed25519Signature, canonical);
        if (!isValid) {
          throw new Error('STATUS_SIGNATURE_TAMPERED: Ed25519 signature verification failed');
        }
      }

      // 3. Domain Allowlist validation
      if (currentHost && !isDomainAllowed(currentHost, payload.allowedDomains)) {
        renderLockOverlay({
          title: 'Domain Unauthorized',
          message: `This domain (${currentHost}) is not authorized to host this application. Please contact support.`,
          contactEmail: payload.contactEmail,
          contactWhatsapp: payload.contactWhatsapp,
          contactPhone: payload.contactPhone,
        });
        return { ok: true, appliedStatus: 'locked_domain_unauthorized' };
      }

      // 4. Status action enforcement
      const status = payload.status || 'active';
      if (status === 'locked') {
        renderLockOverlay({
          title: payload.title || 'Application Access Suspended',
          message: payload.message || 'This application has been suspended.',
          contactEmail: payload.contactEmail,
          contactWhatsapp: payload.contactWhatsapp,
          contactPhone: payload.contactPhone,
          dueAt: payload.dueAt || payload.paymentDueAt,
          lockReason: payload.lockReason,
          autolockState: payload.autolockState,
        });
      } else if (status === 'warning') {
        renderWarningBanner({
          title: payload.title || 'Payment Notice',
          message: payload.message || 'An administrative payment notice is active for this site.',
          contactEmail: payload.contactEmail,
          contactWhatsapp: payload.contactWhatsapp,
        });
      } else {
        // Active
        cleanupDomInterventions();
      }

      return { ok: true, appliedStatus: status, payload };
    } catch (err) {
      console.warn('[DevGuard] Status verification failed:', err.message);

      if (failSafe === 'closed') {
        renderLockOverlay({
          title: 'Security Verification Required',
          message: 'Unable to verify licensing status and fail-safe policy is set to closed.',
        });
        return { ok: false, error: err.message, failSafe: 'closed' };
      }

      // Fail-safe open (default)
      console.info('[DevGuard] Fail-safe open active: website access preserved.');
      return { ok: false, error: err.message, failSafe: 'open' };
    }
  }

  /**
   * Initializes snippet guard.
   */
  function initDevGuardSnippet(customConfig) {
    if (typeof document === 'undefined') return Promise.resolve(null);

    const config = customConfig || extractScriptConfig(document);
    if (!config) return Promise.resolve(null);

    return checkStatus(config).then(function (result) {
      if (config.refreshInterval > 0 && typeof window !== 'undefined') {
        setInterval(function () {
          checkStatus(config);
        }, config.refreshInterval * 1000);
      }
      return result;
    });
  }

  // =========================================================================
  // 7. Auto-boot in Browser
  // =========================================================================

  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () {
        initDevGuardSnippet();
      });
    } else {
      initDevGuardSnippet();
    }
  }

  // =========================================================================
  // 8. Module Exports (CommonJS / ES / Global)
  // =========================================================================

  const api = {
    normalizeHost,
    isDomainAllowed,
    computeStatusCanonicalString,
    decodePublicKey,
    decodeSignature,
    verifyEd25519,
    extractScriptConfig,
    renderWarningBanner,
    renderLockOverlay,
    cleanupDomInterventions,
    checkStatus,
    initDevGuardSnippet,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof global !== 'undefined') {
    global.DevGuardSnippet = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
