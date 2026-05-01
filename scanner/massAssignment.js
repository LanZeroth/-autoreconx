/**
 * AutoReconX — Mass Assignment Scanner
 *
 * Real bug bounty technique:
 *   1. Identify POST/PUT/PATCH endpoints that accept JSON
 *   2. Inject "hidden" administrative fields (isAdmin, role, tier, etc.)
 *   3. Check if the server accepts them (20x status)
 *   4. Check if the injected fields are REFLECTED in the response
 *      → Reflection in the response is a strong signal that the
 *        backend's data model was overwritten.
 */

const axios = require("axios");
const massPayloads = require("../payloads/mass.json");
const { scoreSeverity } = require("./severity");

async function testMassAssignment(endpoint) {
  const findings = [];

  // Only test state-changing methods that typically handle JSON/forms
  const targetMethods = ["POST", "PUT", "PATCH"];
  if (!targetMethods.includes(endpoint.method.toUpperCase())) return findings;

  const extraFields = massPayloads.extraFields || {};
  const fieldKeys   = Object.keys(extraFields);

  if (fieldKeys.length === 0) return findings;

  // ── Step 1: Send request with injected fields ──────────────────
  // We send a minimal valid-looking JSON object with our payloads
  const payload = {
    ...extraFields,
    email: "test-mass@autoreconx.io",
    name:  "AutoReconX Test"
  };

  const response = await safeRequest(endpoint.url, endpoint.method, payload);
  if (!response) return findings;

  // ── Step 2: Analyze response for success and reflection ────────
  const isSuccess = response.status >= 200 && response.status < 300;
  if (!isSuccess) return findings;

  const bodyLower = response.body.toLowerCase();

  // Look for any of our injected values in the response body
  const reflectedFields = fieldKeys.filter(key => {
    const val = String(extraFields[key]).toLowerCase();
    // Match both "key": "value" and "key": value (for booleans)
    return bodyLower.includes(`"${key.toLowerCase()}"`) && bodyLower.includes(val);
  });

  if (reflectedFields.length === 0) return findings;

  // ── Step 3: Determine confidence ──────────────────────────────
  // High confidence if multiple sensitive fields reflected in a 20x response
  const confidence = reflectedFields.length >= 2 ? "Confirmed" : "Likely";

  findings.push({
    type:            "Mass Assignment",
    endpoint:        endpoint.url,
    method:          endpoint.method,
    payload:         JSON.stringify(extraFields),
    reflectedFields,
    snippet:         response.body.slice(0, 250),
    responseSnippet: response.body.slice(0, 250),
    severity:        scoreSeverity("Mass Assignment", response.status, response.body, confidence),
    confidence
  });

  return findings;
}

async function safeRequest(url, method, data) {
  try {
    const res = await axios({
      url,
      method,
      data,
      validateStatus: () => true,
      timeout: 5000,
      headers: {
        "User-Agent": "AutoReconX/1.0 Security Scanner",
        "Content-Type": "application/json"
      }
    });
    const body = typeof res.data === "string"
      ? res.data
      : JSON.stringify(res.data);
    return { status: res.status, body };
  } catch (err) {
    console.warn(`[MassAssignment] Request failed for ${url}: ${err.message}`);
    return null;
  }
}

module.exports = { testMassAssignment };
