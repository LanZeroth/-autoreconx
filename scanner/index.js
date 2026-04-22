const { testIdor } = require("./idor");
const { testXss } = require("./xss");
const { testSsrf } = require("./ssrf");
const { testMassAssignment } = require("./massAssignment");

async function runScans(endpoints, targetUrl, onProgress = () => {}) {
  const findings = [];
  console.log("Endpoints sent to scanner:", endpoints);

  const total = endpoints.length * 4 || 1;
  let done = 0;

  for (const endpoint of endpoints) {
    const checks = [
      () => testIdor(endpoint),
      () => testXss(endpoint),
      () => testSsrf(endpoint),
      () => testMassAssignment(endpoint)
    ];

    for (const check of checks) {
      try {
        const result = await check();

        if (Array.isArray(result) && result.length) {
          findings.push(...result);
        }
      } catch (err) {
        console.error("Scanner runner error:", err.message);
      }

      done += 1;
      onProgress({
        current: done,
        total,
        percent: Math.round((done / total) * 100)
      });
    }
  }

  console.log("Final findings:", findings);
  return findings;
}

module.exports = { runScans };