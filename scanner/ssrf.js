const axios = require("axios");
const ssrfPayloads = require("../payloads/ssrf.json");
const { scoreSeverity } = require("./severity");

async function testSsrf(endpoint) {
  const findings = [];

  if (!endpoint.url || !endpoint.url.includes("?")) {
    return findings;
  }

  const url = new URL(endpoint.url);

  for (const param of ssrfPayloads.commonParams) {
    if (!url.searchParams.has(param)) continue;

    for (const payload of ssrfPayloads.urls) {
      const mutated = new URL(endpoint.url);
      mutated.searchParams.set(param, payload);

      try {
        const res = await axios.get(mutated.toString(), {
          validateStatus: () => true,
          timeout: 4000
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

        if (body.includes("internal-demo-resource")) {
          findings.push({
            type: "SSRF",
            endpoint: mutated.toString(),
            payload,
            responseSnippet: body.slice(0, 140),
            severity: scoreSeverity("SSRF", res.status, body),
            confidence: "Confirmed (demo target only)"
          });
        }
      } catch (err) {
  console.error("Scanner error:", err.message);
}
    }
  }

  return findings;
}

module.exports = { testSsrf };