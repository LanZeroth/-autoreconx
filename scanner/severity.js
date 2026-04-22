function scoreSeverity(type, status, body) {
  const text = String(body || "").toLowerCase();

  if (type === "SSRF" && text.includes("internal-demo-resource")) {
    return "High";
  }

  if (type === "IDOR" && status === 200) {
    return "High";
  }

  if (type === "Mass Assignment" && (text.includes("admin") || text.includes("isadmin"))) {
    return "High";
  }

  if (type === "XSS" && text.includes("autoreconx")) {
    return "Medium";
  }

  return "Low";
}

module.exports = { scoreSeverity };