const axios = require("axios");
const xssPayloads = require("../payloads/xss.json");
const { scoreSeverity } = require("./severity");

async function testXss(endpoint) {
  const findings = [];

  if (!endpoint.url || !endpoint.url.includes("?")) {
    return findings;
  }

  const url = new URL(endpoint.url);

  for (const [key] of url.searchParams.entries()) {
    for (const payload of xssPayloads.markers) {
      const mutated = new URL(endpoint.url);
      mutated.searchParams.set(key, payload);

      try {
        const res = await axios.get(mutated.toString(), {
          validateStatus: () => true,
          timeout: 4000
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

        if (body.includes(payload)) {
          findings.push({
            type: "XSS",
            endpoint: mutated.toString(),
            payload,
            responseSnippet: body.slice(0, 140),
            severity: scoreSeverity("XSS", res.status, body),
            confidence: payload.includes("<script>") ? "Likely" : "Potential"
          });
        }
      } catch (err) {
  console.error("Scanner error:", err.message);
}
    }
  }

  return findings;
}

module.exports = { testXss };