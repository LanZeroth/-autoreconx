const { pentestTemplate, hackerOneTemplate, normalizeSeverity } = require("./templates");

function inferCwe(type = "") {
  const t = String(type).toLowerCase();

  if (t.includes("idor")) return "CWE-639";
  if (t.includes("xss")) return "CWE-79";
  if (t.includes("sqli") || t.includes("sql injection")) return "CWE-89";
  if (t.includes("ssrf")) return "CWE-918";
  if (t.includes("csrf")) return "CWE-352";
  if (t.includes("open redirect")) return "CWE-601";
  if (t.includes("command injection")) return "CWE-77";
  if (t.includes("path traversal")) return "CWE-22";
  if (t.includes("secret") || t.includes("api key")) return "CWE-798";

  return "Not mapped";
}

function buildNarrative(finding) {
  const endpoint = finding.endpoint || finding.asset || "the affected endpoint";
  const param = finding.parameter ? ` by modifying the parameter "${finding.parameter}"` : "";
  const behavior = finding.behavior || "the application returned behavior suggesting a security weakness";
  return `During testing of ${endpoint}, an attacker could interact with the application${param}, and ${behavior}. This suggests that trust is being placed in user-controlled input without sufficient server-side protection.`;
}

function normalizeFinding(raw = {}) {
  return {
    title: raw.title || raw.name || raw.type || "Untitled Finding",
    asset: raw.asset || raw.target || raw.url || "Unknown",
    endpoint: raw.endpoint || raw.path || raw.url || "Unknown",
    severity: normalizeSeverity(raw.severity || raw.risk || ""),
    cwe: raw.cwe || inferCwe(raw.type || raw.title || ""),
    summary: raw.summary || raw.description || "A potential vulnerability was detected by AutoReconX.",
    description: raw.description || raw.summary || "",
    attackNarrative: raw.attackNarrative || buildNarrative(raw),
    reproductionSteps: raw.reproductionSteps || raw.steps || [],
    request: raw.request || raw.rawRequest || "",
    response: raw.response || raw.rawResponse || "",
    evidence: raw.evidence || raw.notes || "",
    impact: raw.impact || "Successful exploitation could allow unauthorized behavior against the affected application flow.",
    businessImpact: raw.businessImpact || "This may expose sensitive data, weaken trust boundaries, or increase operational risk.",
    remediation: raw.remediation || "Review validation and authorization logic for the affected functionality.",
    references: raw.references || [],
    environment: raw.environment || "Web application endpoint tested through AutoReconX.",
    poc: raw.poc || raw.proof || "Follow the reproduction steps and compare the observed response."
  };
}

function generateReports(rawFinding) {
  const finding = normalizeFinding(rawFinding);

  return {
    meta: {
      title: finding.title,
      severity: finding.severity,
      asset: finding.asset,
      endpoint: finding.endpoint,
      cwe: finding.cwe
    },
    pentestMarkdown: pentestTemplate(finding),
    hackeroneMarkdown: hackerOneTemplate(finding)
  };
}

module.exports = {
  generateReports,
  normalizeFinding,
  inferCwe
};