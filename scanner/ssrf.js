/**
 * AutoReconX — SSRF Scanner
 *
 * Real bug bounty technique:
 *   Multi-signal detection — don't rely on a single magic string.
 *   An SSRF might reveal itself through:
 *     1. Response body containing internal content/keywords
 *     2. Unusual response time (server is making an outbound call)
 *     3. HTTP status codes that only make sense server-side (e.g. 200 for an internal IP)
 *     4. Error messages that leak the internal fetch attempt
 *     5. Content-Type mismatch (fetched internal JSON served as HTML page)
 *
 * We also check URL-like params that aren't in our list (heuristic scan).
 */

const axios = require("axios");
const ssrfPayloads = require("../payloads/ssrf.json");
const { scoreSeverity } = require("./severity");

// Keywords that signal internal resource access
const INTERNAL_SIGNALS = [
  "internal-demo-resource",   // Our demo target
  "ami-id",                   // AWS EC2 metadata
  "instance-id",              // AWS EC2 metadata
  "local-hostname",           // AWS EC2 metadata
  "iam/security-credentials", // AWS IAM
  "computeMetadata",          // GCP metadata
  "metadata.google",          // GCP metadata
  "169.254.169.254",          // Metadata IP in response
  "root:x:0:0",               // /etc/passwd leak
  "Connection refused",       // Internal port probe
  "ECONNREFUSED",             // Node.js internal connection error
  "getaddrinfo ENOTFOUND",    // DNS resolution failure (confirms fetch attempt)
  "failed to connect",        // Generic internal fetch failure
];

// Error messages that confirm the server attempted an SSRF fetch
const FETCH_ERROR_SIGNALS = [
  "could not connect",
  "connection timed out",
  "invalid url",
  "name or service not known",
  "no route to host",
  "network is unreachable",
];

async function testSsrf(endpoint) {
  const findings = [];

  if (!endpoint.url || !endpoint.url.includes("?")) return findings;

  let url;
  try {
    url = new URL(endpoint.url);
  } catch {
    return findings;
  }

  // ── Find URL-accepting params: explicit list + heuristic ──────
  const urlParams = findUrlParams(url);
  if (urlParams.length === 0) return findings;

  for (const param of urlParams) {
    for (const payloadValue of ssrfPayloads.urls) {
      const mutated = new URL(endpoint.url);
      mutated.searchParams.set(param, payloadValue);

      const startMs  = Date.now();
      const response = await safeGet(mutated.toString());
      const elapsed  = Date.now() - startMs;

      if (!response) continue;

      // ── Signal 1: Body contains internal content ───────────────
      const bodyLower  = response.body.toLowerCase();
      const bodySignal = INTERNAL_SIGNALS.find(s => bodyLower.includes(s.toLowerCase()));

      // ── Signal 2: Response time anomaly ───────────────────────
      // Internal fetches take time; quick 404s are usually just missing pages
      const timingAnomaly = elapsed > 2500 && response.status !== 404;

      // ── Signal 3: Error message confirms server made a request ─
      const errorSignal = FETCH_ERROR_SIGNALS.find(s => bodyLower.includes(s));

      // ── Signal 4: Unexpected success on internal URL ───────────
      const internalPayload = payloadValue.includes("127.0.0.1") ||
                              payloadValue.includes("localhost") ||
                              payloadValue.includes("169.254") ||
                              payloadValue.includes("192.168") ||
                              payloadValue.includes("10.0");
      const unexpectedSuccess = internalPayload && response.status === 200;

      const triggered = bodySignal || errorSignal || unexpectedSuccess;
      if (!triggered && !timingAnomaly) continue;

      // ── Determine confidence from signal strength ──────────────
      let confidence = "Potential";
      if (bodySignal && INTERNAL_SIGNALS.slice(0, 8).includes(bodySignal)) {
        confidence = "Confirmed"; // Hard internal content seen
      } else if (unexpectedSuccess || errorSignal) {
        confidence = "Likely";
      }

      findings.push({
        type:            "SSRF",
        endpoint:        mutated.toString(),
        param,
        payload:         payloadValue,
        signals: {
          bodySignal:      bodySignal || null,
          timingAnomaly:   timingAnomaly ? `${elapsed}ms` : null,
          errorSignal:     errorSignal  || null,
          unexpectedSuccess
        },
        snippet:         response.body.slice(0, 200),
        responseSnippet: response.body.slice(0, 200),
        severity:        scoreSeverity("SSRF", response.status, response.body, confidence),
        confidence
      });

      // One finding per param — don't pile on with more payloads
      break;
    }
  }

  return findings;
}

// ──────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────

/**
 * Find params that are likely to accept URLs.
 * Combines explicit allowlist + heuristic name matching.
 */
function findUrlParams(url) {
  const explicit = ssrfPayloads.commonParams;

  // Heuristic: param names that strongly suggest URL handling
  const urlParamPatterns = [
    /^url$/i, /^uri$/i, /^src$/i, /^href$/i, /^link$/i,
    /^target$/i, /^redirect$/i, /^next$/i, /^return$/i,
    /^fetch$/i, /^load$/i, /^img$/i, /^image$/i,
    /^file$/i, /^path$/i, /^resource$/i, /^endpoint$/i,
    /^callback$/i, /^proxy$/i, /^forward$/i, /^destination$/i
  ];

  const heuristic = [];
  for (const [key, value] of url.searchParams.entries()) {
    // Match by name pattern
    if (urlParamPatterns.some(p => p.test(key))) {
      heuristic.push(key);
      continue;
    }
    // Match by value — if the param value looks like a URL
    if (/^https?:\/\//i.test(value) || /^\/\//.test(value)) {
      heuristic.push(key);
    }
  }

  // Combine and dedupe
  return [...new Set([...explicit, ...heuristic])].filter(p =>
    url.searchParams.has(p)
  );
}

async function safeGet(url) {
  try {
    const res = await axios.get(url, {
      validateStatus: () => true,
      timeout: 6000,
      headers: { "User-Agent": "AutoReconX/1.0 Security Scanner" },
      maxRedirects: 2  // Limit redirects — SSRF via redirect is its own class
    });
    const body = typeof res.data === "string"
      ? res.data
      : JSON.stringify(res.data);
    return { status: res.status, body };
  } catch (err) {
    // Connection errors are themselves SSRF signals — capture them
    return {
      status: 0,
      body: err.message || ""
    };
  }
}

module.exports = { testSsrf };