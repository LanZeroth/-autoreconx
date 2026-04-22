function formatFindings(findings) {
  return findings.map((item, index) => ({
    id: index + 1,
    vulnerability: item.type,
    endpoint: item.endpoint,
    payload: item.payload,
    responseSnippet: item.responseSnippet,
    severity: item.severity,
    confidence: item.confidence || "Potential"
  }));
}

module.exports = { formatFindings };