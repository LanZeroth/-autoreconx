const axios = require("axios");
const idorPayloads = require("../payloads/idor.json");
const { scoreSeverity } = require("./severity");

async function testIdor(endpoint) {
  const findings = [];

  if (!endpoint.url || !endpoint.url.includes("?")) {
    return findings;
  }

  const url = new URL(endpoint.url);

  for (const [key, value] of url.searchParams.entries()) {
    if (!idorPayloads.commonParams.includes(key)) continue;
    if (!/^\d+$/.test(value)) continue;

    for (const offset of idorPayloads.numericOffsets) {
      const mutated = new URL(endpoint.url);
      mutated.searchParams.set(key, String(Number(value) + offset));

      try {
        const res = await axios.get(mutated.toString(), {
          validateStatus: () => true,
          timeout: 4000
        });

        const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

        if (res.status === 200 && body.length > 0) {
          findings.push({
            type: "IDOR",
            endpoint: mutated.toString(),
            payload: `${key}=${Number(value) + offset}`,
            responseSnippet: body.slice(0, 140),
            severity: scoreSeverity("IDOR", res.status, body),
            confidence: "Potential"
          });
        }
      } catch (err) {
  console.error("Scanner error:", err.message);
}
    }
  }

  return findings;
}

module.exports = { testIdor };