const axios = require("axios");
const massPayloads = require("../payloads/mass.json");
const { scoreSeverity } = require("./severity");

async function testMassAssignment(endpoint) {
  const findings = [];

  if (!endpoint.url) {
    return findings;
  }

  const isLikelyWriteEndpoint =
    endpoint.method === "POST" ||
    endpoint.method === "PUT" ||
    endpoint.url.includes("/register") ||
    endpoint.url.includes("/user") ||
    endpoint.url.includes("/create");

  if (!isLikelyWriteEndpoint) {
    return findings;
  }

  const requestBody = {
    name: "demo-user",
    email: "demo@example.com",
    ...massPayloads.extraFields
  };

  try {
    const method = endpoint.method && ["POST", "PUT"].includes(endpoint.method)
      ? endpoint.method.toLowerCase()
      : "post";

    const res = await axios({
      method,
      url: endpoint.url,
      data: requestBody,
      headers: {
        "Content-Type": "application/json"
      },
      validateStatus: () => true,
      timeout: 4000
    });

    const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);

    if (body.includes("admin") || body.includes("isAdmin") || body.includes("enterprise")) {
      findings.push({
        type: "Mass Assignment",
        endpoint: endpoint.url,
        payload: JSON.stringify(massPayloads.extraFields),
        responseSnippet: body.slice(0, 140),
        severity: scoreSeverity("Mass Assignment", res.status, body),
        confidence: "Likely"
      });
    }
  } catch (err) {
  console.error("Scanner error:", err.message);
}

  return findings;
}

module.exports = { testMassAssignment };