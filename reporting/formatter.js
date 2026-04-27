function normalizeSeverity(severity = "") {
  const s = String(severity).toLowerCase();
  if (["critical", "high", "medium", "low", "informational"].includes(s)) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  return "Needs validation";
}

function inferCwe(finding = {}) {
  const text = `${finding.type || ""} ${finding.title || ""}`.toLowerCase();
  if (text.includes("idor")) return "CWE-639";
  if (text.includes("xss")) return "CWE-79";
  if (text.includes("ssrf")) return "CWE-918";
  if (text.includes("mass")) return "CWE-915";
  return "Not mapped";
}

function normalizeFinding(finding = {}) {
  return {
    title: finding.title || finding.type || "Untitled Finding",
    type: finding.type || "Unknown",
    endpoint: finding.endpoint || finding.url || "Unknown",
    payload: finding.payload || "",
    snippet: finding.snippet || "",
    severity: normalizeSeverity(finding.severity),
    cwe: finding.cwe || inferCwe(finding),
    description:
      finding.description ||
      `AutoReconX detected a potential ${finding.type || "security"} issue at ${finding.endpoint || "an endpoint"}.`,
    impact:
      finding.impact ||
      "This issue may allow unintended application behavior and should be manually validated.",
    remediation:
      finding.remediation ||
      "Review input validation, output encoding, and authorization controls for the affected endpoint.",
    reproductionSteps:
      finding.reproductionSteps || [
        `Open the affected endpoint: ${finding.endpoint || "unknown endpoint"}`,
        "Repeat the request with the observed payload or modified input.",
        "Observe the response behavior that indicates the issue."
      ],
    request: finding.request || "",
    response: finding.response || "",
    references: finding.references || []
  };
}

function formatFindings(findings = []) {
  return findings.map(normalizeFinding);
}

function formatPentestReport(findings = [], target = "") {
  const normalized = formatFindings(findings);

  if (!normalized.length) {
    return `# Pentest Report

## Overview
The scan for ${target || "the provided target"} completed successfully and returned no findings.

## Scope
- Target: ${target || "Unknown"}

## Conclusion
No supported vulnerability patterns were detected during this scan. Manual verification is still recommended.
`;
  }

  const body = normalized.map((f, index) => `## Finding ${index + 1}: ${f.title}

### Affected Endpoint
- Endpoint: ${f.endpoint}
- Severity: ${f.severity}
- CWE: ${f.cwe}

### Description
${f.description}

### Steps to Reproduce
${f.reproductionSteps.map((step, i) => `${i + 1}. ${step}`).join("\n")}

### Evidence
- Payload: ${f.payload || "N/A"}
- Snippet: ${f.snippet || "N/A"}

### Impact
${f.impact}

### Remediation
${f.remediation}

### References
${f.references.length ? f.references.map(r => `- ${r}`).join("\n") : "- None provided"}
`).join("\n");

  return `# Pentest Report

## Overview
AutoReconX identified ${normalized.length} potential issue(s) on ${target || "the provided target"}.

## Scope
- Target: ${target || "Unknown"}

## Method
The assessment used AutoReconX crawler and scanner modules to review reachable endpoints and test supported payload classes.

${body}
`;
}

function formatHackerOneReport(findings = [], target = "") {
  const normalized = formatFindings(findings);

  if (!normalized.length) {
    return `## Summary
The scan of ${target || "the provided target"} did not produce any findings that currently map to a supported report.

## Target
- Asset: ${target || "Unknown"}

## Impact
No confirmed issue is available for submission.
`;
  }

  const top = normalized[0];

  return `## Summary
A potential ${top.title} vulnerability was identified on ${target || "the provided target"} at ${top.endpoint}.

## Target
- Asset: ${target || "Unknown"}
- Endpoint: ${top.endpoint}
- Severity: ${top.severity}
- CWE: ${top.cwe}

## Steps to Reproduce
${top.reproductionSteps.map((step, i) => `${i + 1}. ${step}`).join("\n")}

## Proof of Concept
Payload used: ${top.payload || "N/A"}

Observed response snippet:
${top.snippet || "N/A"}

## Impact
${top.impact}

## Remediation
${top.remediation}

## Supporting Material
${top.references.length ? top.references.map(r => `- ${r}`).join("\n") : "- None provided"}
`;
}

module.exports = {
  formatFindings,
  formatPentestReport,
  formatHackerOneReport
};