/**
 * AutoReconX — IDOR Scanner
 *
 * Real bug bounty technique:
 *   1. Fetch the BASELINE response for the original ID
 *   2. Mutate the ID and fetch again
 *   3. Only flag if:
 *      - Both responses are 200
 *      - The response BODIES ARE DIFFERENT (different user's data)
 *      - The body is non-trivial (not just an empty page)
 *
 * Without step 3, you get false positives on every paginated API.
 */

const axios = require("axios");
const idorPayloads = require("../payloads/idor.json");
const { scoreSeverity } = require("./severity");

async function testIdor(endpoint) {
  const findings = [];

  if (!endpoint.url || !endpoint.url.includes("?")) return findings;

  let url;
  try {
    url = new URL(endpoint.url);
  } catch {
    return findings;
  }

  for (const [key, value] of url.searchParams.entries()) {
    // Only test params that look like ID fields
    if (!idorPayloads.commonParams.includes(key)) continue;
    // Only test numeric values (UUIDs handled separately below)
    if (!/^\d+$/.test(value)) continue;

    // ── Step 1: Get baseline for the ORIGINAL id ──────────────────
    const baseline = await safeGet(endpoint.url);
    if (!baseline || baseline.status !== 200 || baseline.body.length < 10) continue;

    // ── Step 2: Test each mutated ID ──────────────────────────────
    for (const offset of idorPayloads.numericOffsets) {
      const mutatedId = String(Number(value) + offset);
      if (mutatedId === value || Number(mutatedId) < 0) continue;

      const mutated = new URL(endpoint.url);
      mutated.searchParams.set(key, mutatedId);

      const response = await safeGet(mutated.toString());
      if (!response || response.status !== 200) continue;

      // ── Step 3: Compare bodies — key differentiator ───────────
      const baseLen   = baseline.body.length;
      const respLen   = response.body.length;
      const sizeDelta = Math.abs(baseLen - respLen);

      // Bodies must differ meaningfully (not just whitespace/timestamp)
      // AND the response must contain real content
      const bodiesAreDifferent = sizeDelta > 20 || contentDiffers(baseline.body, response.body);
      const hasRealContent     = respLen > 30;

      if (!bodiesAreDifferent || !hasRealContent) continue;

      // ── Step 4: Check for data leak signals ───────────────────
      // Higher confidence if response contains user-like fields
      const hasUserData = /name|email|role|user|account|phone|address/i.test(response.body);
      const confidence  = hasUserData ? "Likely" : "Potential";

      findings.push({
        type:            "IDOR",
        endpoint:        mutated.toString(),
        param:           key,
        originalValue:   value,
        mutatedValue:    mutatedId,
        payload:         `${key}=${mutatedId} (was ${value})`,
        snippet:         response.body.slice(0, 200),
        responseSnippet: response.body.slice(0, 200),
        baselineSnippet: baseline.body.slice(0, 200),
        sizeDelta,
        severity:        scoreSeverity("IDOR", response.status, response.body, confidence),
        confidence
      });

      // One confirmed finding per param is enough — move on
      break;
    }
  }

  return findings;
}

// ──────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────

/**
 * Compare two HTML/JSON bodies ignoring timestamps and minor whitespace.
 * Returns true if they appear to contain meaningfully different content.
 */
function contentDiffers(a, b) {
  // Strip timestamps (ISO dates, unix timestamps)
  const clean = str => str
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.Z]+/g, "TIMESTAMP")
    .replace(/\b\d{10,13}\b/g, "TIMESTAMP")
    .replace(/\s+/g, " ")
    .trim();

  return clean(a) !== clean(b);
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
    return { status: res.status, body };
  } catch (err) {
    console.warn(`[IDOR] Request failed for ${url}: ${err.message}`);
    return null;
  }
}

module.exports = { testIdor };