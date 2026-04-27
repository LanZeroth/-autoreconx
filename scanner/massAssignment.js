/**
 * AutoReconX — Severity Scorer
 *
 * Old problem: severity was hardcoded to demo-specific strings
 * ("internal-demo-resource", "autoreconx") — useless against real targets.
 *
 * New approach: rule-based scoring using transferable signals.
 *
 * Scoring model (mirrors CVSS-lite logic used in bug bounty triage):
 *   Base score per vuln type
 *   + confidence modifier
 *   + data sensitivity signals in response
 *   + endpoint sensitivity (admin, auth, payment routes)
 *
 * Output: "Critical" | "High" | "Medium" | "Low"
 */

// ── Sensitivity signals in response body ──────────────────────
// Presence of these in the mutated response = more severe
const SENSITIVE_DATA_PATTERNS = [
  /password/i,
  /passwd/i,
  /secret/i,
  /api[_-]?key/i,
  /auth[_-]?token/i,
  /access[_-]?token/i,
  /private[_-]?key/i,
  /credit[_-]?card/i,
  /ssn/i,
  /social.security/i,
  /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/,  // Card number pattern
  /root:x:0:0/,                                  // /etc/passwd
  /ami-id/i,                                     // AWS metadata
  /instance-id/i,
  /iam\/security/i,
];

// ── High-value endpoint indicators ────────────────────────────
const SENSITIVE_ENDPOINT_PATTERNS = [
  /\/admin/i,
  /\/internal/i,
  /\/payment/i,
  /\/billing/i,
  /\/checkout/i,
  /\/auth/i,
  /\/login/i,
  /\/token/i,
  /\/secret/i,
  /\/config/i,
  /\/settings/i,
  /\/manage/i,
];

/**
 * @param {string} type        - Vulnerability class
 * @param {number} status      - HTTP status of the finding response
 * @param {string} body        - Response body text
 * @param {string} confidence  - "Confirmed" | "Likely" | "Potential"
 * @param {string} [endpoint]  - Endpoint URL (optional, for context bonus)
 * @returns {"Critical"|"High"|"Medium"|"Low"}
 */
function scoreSeverity(type, status, body = "", confidence = "Potential", endpoint = "") {
  let score = baseScore(type);

  // ── Confidence modifier ──────────────────────────────────────
  if (confidence === "Confirmed") score += 2;
  else if (confidence === "Likely")   score += 1;
  else if (confidence === "Potential") score -= 1;

  // ── Sensitive data in response → raise the stakes ────────────
  const bodyText = String(body);
  if (SENSITIVE_DATA_PATTERNS.some(p => p.test(bodyText))) {
    score += 2;
  }

  // ── Sensitive endpoint → higher impact ───────────────────────
  if (endpoint && SENSITIVE_ENDPOINT_PATTERNS.some(p => p.test(endpoint))) {
    score += 1;
  }

  // ── Type-specific modifiers ───────────────────────────────────

  if (type === "SSRF") {
    // Blind SSRF (no content leaked) is still High
    // SSRF with internal content is Critical
    if (/ami-id|instance-id|root:x:0:0|computeMetadata/i.test(bodyText)) score += 2;
  }

  if (type === "IDOR") {
    // Accessing another user's data = confirmed data breach
    if (status === 200) score += 1;
    // Admin data visible = Critical
    if (/admin|superuser|role.*admin/i.test(bodyText)) score += 2;
  }

  if (type === "XSS") {
    // Stored XSS > Reflected (we can't distinguish here, but context helps)
    if (/script-block|attribute/i.test(confidence)) score += 1;
  }

  if (type === "Mass Assignment") {
    // Privilege escalation confirmed
    if (/admin.*true|isAdmin.*true|role.*admin/i.test(bodyText)) score += 2;
  }

  // ── Map numeric score to label ─────────────────────────────────
  return scoreToLabel(score);
}

function baseScore(type) {
  const bases = {
    "SSRF":            7,
    "IDOR":            6,
    "Mass Assignment": 6,
    "XSS":             5,
  };
  return bases[type] || 4;
}

function scoreToLabel(score) {
  if (score >= 10) return "Critical";
  if (score >= 7)  return "High";
  if (score >= 4)  return "Medium";
  return "Low";
}

module.exports = { scoreSeverity, SENSITIVE_DATA_PATTERNS };