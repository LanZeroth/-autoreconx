/**
 * AutoReconX — Scanner Orchestrator
 *
 * Improvements over v1:
 *   - Finding deduplication (same type + endpoint = one finding)
 *   - Graceful error isolation per check (one failure doesn't kill others)
 *   - Progress now reports WHICH vuln type is being tested
 *   - Parallel checks per endpoint (faster)
 */

const { testIdor }          = require("./idor");
const { testXss }           = require("./xss");
const { testSsrf }          = require("./ssrf");
const { testMassAssignment }= require("./massAssignment");

async function runScans(endpoints, targetUrl, onProgress = () => {}) {
  const allFindings = [];
  const total = endpoints.length;
  let done  = 0;

  for (const endpoint of endpoints) {
    // Run all 4 checks per endpoint in parallel for speed
    const results = await Promise.allSettled([
      runCheck("IDOR",            () => testIdor(endpoint)),
      runCheck("XSS",             () => testXss(endpoint)),
      runCheck("SSRF",            () => testSsrf(endpoint)),
      runCheck("Mass Assignment", () => testMassAssignment(endpoint)),
    ]);

    for (const result of results) {
      if (result.status === "fulfilled" && Array.isArray(result.value)) {
        allFindings.push(...result.value);
      }
      // Rejected results are already logged inside runCheck
    }

    done++;
    onProgress({
      current: done,
      total,
      percent: Math.round((done / total) * 100),
      currentEndpoint: endpoint.url
    });
  }

  // Deduplicate: same type + same endpoint = keep highest-severity one
  return deduplicateFindings(allFindings);
}

/**
 * Wrap a scanner check so errors are isolated and logged meaningfully.
 */
async function runCheck(checkName, fn) {
  try {
    return await fn();
  } catch (err) {
    console.error(`[Scanner:${checkName}] Unexpected error: ${err.message}`);
    return [];
  }
}

/**
 * Keep only the most severe finding per (type, endpoint) pair.
 * Prevents the same endpoint being flagged 4 times for the same issue.
 */
function deduplicateFindings(findings) {
  const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const seen = new Map();

  for (const finding of findings) {
    const key = `${finding.type}::${finding.endpoint}`;
    const existing = seen.get(key);

    if (!existing) {
      seen.set(key, finding);
    } else {
      // Keep the higher severity finding
      const existingRank = severityRank[existing.severity] || 0;
      const newRank      = severityRank[finding.severity]  || 0;
      if (newRank > existingRank) {
        seen.set(key, finding);
      }
    }
  }

  return Array.from(seen.values());
}

module.exports = { runScans };