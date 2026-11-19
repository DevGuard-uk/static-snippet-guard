# @devguard/static-snippet-guard

> Zero-build, drop-in static HTML `<script>` tag licensing guard for static sites, Jamstack, Jekyll, Astro, Hugo, and Webflow exports.

Protects static web assets through:
- **Asymmetric Ed25519 Cryptography**: Server status responses are signed with the developer's private key. The browser verifies the payload with the developer's public key, preventing DevTools manipulation or forged `active` responses.
- **Domain Lock**: Validates `window.location.hostname` against `allowedDomains` with wildcard and port support.
- **Tamper-Resistant Lock Screen**: Full-screen overlay (`z-index: 2147483647`) guarded by a DOM `MutationObserver` that automatically detects and reverses removal or CSS hiding in DevTools.
- **Non-Intrusive Warning Banner**: Injects a sticky notice for pending payments without interrupting site usability.
- **Fail-Safe Open**: Network errors or API cluster outages default to keeping the site online (unless configured as `closed`).
- **Zero Dependencies & Ultra-Lightweight**: Under 15KB uncompressed (<5KB gzipped), native WebCrypto support.

---

## Quick Start

Add the single `<script>` tag inside your HTML `<head>` or before `</body>`:

```html
<script 
  src="https://cdn.devguard.uk/snippet/v1/devguard-snippet.min.js"
  data-project-id="YOUR_PROJECT_ID"
  data-public-key="YOUR_ED25519_PUBLIC_KEY"
  data-api-url="https://api.devguard.uk"
  data-fail-safe="open"
  defer>
</script>
```

---

## Configuration Attributes

| Attribute | Required | Default | Description |
|---|---|---|---|
| `data-project-id` | **Yes** | — | Project ID registered in DevGuard Console. |
| `data-public-key` | **Yes** | — | 32-byte Ed25519 Developer Public Key in hex (`64 chars`), SPKI PEM, or base64 format. |
| `data-api-url` | No | `https://api.devguard.uk` | API gateway endpoint. Supports proxies or custom clusters. |
| `data-fail-safe` | No | `open` | Fail-safe policy on network failure: `"open"` (site stays up) or `"closed"` (locks site). |
| `data-max-skew` | No | `300` | Max allowed clock skew in seconds between client and API server timestamp. |
| `data-refresh-interval` | No | `0` | Background polling interval in seconds (`0` = check once on load). |

---

## Example Static HTML Integration

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Client Showcase Portfolio</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <!-- DevGuard Static Snippet Guard -->
  <script 
    src="https://cdn.devguard.uk/snippet/v1/devguard-snippet.min.js" 
    data-project-id="dg-proj-84f932" 
    data-public-key="f12300ca1a84c9b151db07759b0b3b181040dc8df135ecd347574518dcf5cf0e"
    data-api-url="https://api.devguard.uk" 
    data-fail-safe="open"
    defer>
  </script>
</head>
<body>
  <h1>Client Portfolio</h1>
  <p>Static Jamstack website protected by DevGuard.</p>
</body>
</html>
```

---

## Building from Source

```bash
# Minify and bundle to dist/devguard-snippet.min.js
node scripts/build.js
```

## License

Apache-2.0 © DevGuard Team
