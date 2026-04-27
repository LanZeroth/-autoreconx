/**
 * AutoReconX — XSS Scanner
 *
 * Real bug bounty technique:
 *   1. Use a UNIQUE marker per test (not a shared payload string)
 *      → eliminates false positives from cached/static content
 *   2. Check WHERE the payload lands in the response:
 *      - In HTML body text    → High (executes directly)
 *      - In an attribute      → Medium (may need closing quote)
 *      - In a script block    → High (already in JS context)
 *      - HTML-encoded         → Low / false positive
 *   3. Confirm Content-Type is text/html (JSON reflection ≠ XSS)
 */

const axios = require("axios");
const xssPayloads = require("../payloads/xss.json");
const { scoreSeverity } = require("./severity");

async function testXss(endpoint) {
  const findings = [];

  if (!endpoint.url || !endpoint.url.includes("?")) return findings;

  let url;
  try {
    url = new URL(endpoint.url);
  } catch {
    return findings;
  }

  for (const [key] of url.searchParams.entries()) {
    for (const payload of xssPayloads.markers) {
      // Use a unique nonce so we know this specific request caused the reflection
      const nonce   = Math.random().toString(36).slice(2, 8);
      const tagged  = payload.replace("NONCE", nonce);

      const mutated = new URL(endpoint.url);
      mutated.searchParams.set(key, tagged);

      const response = await safeGet(mutated.toString());
      if (!response) continue;

      // ── Must be HTML to be exploitable as XSS ─────────────────
      const contentType = response.contentType || "";
      const isHtml      = contentType.includes("text/html") ||
                          response.body.trimStart().startsWith("<");

      if (!isHtml) continue;

      // ── Check if payload appears UNENCODED in the response ────
      // HTML-encoded versions (&lt; &gt; &#x3C; etc.) are NOT exploitable
      const rawReflected     = response.body.includes(tagged);
      const encodedVersion   = htmlEncode(tagged);
      const onlyEncoded      = !rawReflected && response.body.includes(encodedVersion);

      if (!rawReflected || onlyEncoded) continue;

      // ── Determine reflection CONTEXT for accurate severity ────
      const context    = getReflectionContext(response.body, tagged);
      const confidence = getConfidence(payload, context);
      const snippet    = extractSnippet(response.body, tagged, 200);

      findings.push({
        type:            "XSS",
        endpoint:        mutated.toString(),
        param:           key,
        payload:         tagged,
        payloadTemplate: payload,
        context,           // "html-body" | "attribute" | "script-block" | "unknown"
        responseSnippet: snippet,
        severity:        scoreSeverity("XSS", response.status, response.body, confidence),
        confidence
      });

      // One confirmed finding per param is sufficient
      break;
    }
  }

  return findings;
}

// ──────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────

/**
 * Where in the HTML does the payload land?
 * This drives both confidence and remediation advice.
 */
function getReflectionContext(body, payload) {
  const idx = body.indexOf(payload);
  if (idx === -1) return "unknown";

  // Grab surrounding 200 chars
  const surrounding = body.slice(Math.max(0, idx - 100), idx + payload.length + 100);

  if (/<script[\s>]/i.test(surrounding.slice(0, 100))) return "script-block";
  if (/\s[\w-]+=["'][^"']*$/.test(surrounding.slice(0, idx - Math.max(0, idx - 100))))
    return "attribute";
  return "html-body";
}

/**
 * Confidence is based on CONTEXT + payload type, not just payload string.
 * Event handlers in HTML body = more reliable than raw script tags
 * (many WAFs block <script> but miss onerror=).
 */
function getConfidence(payloadTemplate, context) {
  const isEventHandler = /on\w+=/i.test(payloadTemplate);
  const isScriptTag    = /<script/i.test(payloadTemplate);
  const isSvg          = /<svg/i.test(payloadTemplate);

  if (context === "script-block")                    return "High";
  if (context === "html-body" && isEventHandler)     return "Likely";
  if (context === "html-body" && isScriptTag)        return "Likely";
  if (context === "attribute" && isEventHandler)     return "Likely";
  if (isSvg && context === "html-body")              return "Likely";
  return "Potential";
}

/**
 * Extract surrounding context of the reflection for the report snippet.
 */
function extractSnippet(body, payload, maxLen) {
  const idx = body.indexOf(payload);
  if (idx === -1) return body.slice(0, maxLen);
  const start = Math.max(0, idx - 60);
  const end   = Math.min(body.length, idx + payload.length + 60);
  return `...${body.slice(start, end)}...`;
}

function htmlEncode(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function safeGet(url) {
  try {
    const res = await axios.get(url, {
      validateStatus: () => true,
      timeout: 5000,
      headers: { "User-Agent": "AutoReconX/1.0 Security Scanner" }
    });
    const body = typeof res.data === "string"
      ? res.data
      : JSON.stringify(res.data);
    return {
      status:      res.status,
      body,
      contentType: res.headers["content-type"] || ""
    };
  } catch (err) {
    console.warn(`[XSS] Request failed for ${url}: ${err.message}`);
    return null;
  }
}

module.exports = { testXss };