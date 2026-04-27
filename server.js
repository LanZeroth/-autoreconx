require("dotenv").config();

const express = require("express");
const path = require("path");
const { crawl } = require("./crawler/crawl");
const { runScans } = require("./scanner");
const { formatFindings } = require("./reporting/formatter");
const { exportJson } = require("./reporting/exporter");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const scans = new Map();

function buildFallbackReply(message, findings = [], targetUrl = "") {
  const text = (message || "").toLowerCase();

  if (
    text.includes("0 finding") ||
    text.includes("0 result") ||
    text.includes("no finding") ||
    text.includes("why")
  ) {
    return `If the scan completed with 0 findings, confirm the demo target is running on http://localhost:4001 and that you scanned the correct URL. If the target is up and you still see no findings, the current checks may not have matched any test patterns on that page.`;
  }

  if (
    text.includes("demo target") ||
    text.includes("target url") ||
    text.includes("which url") ||
    text.includes("localhost")
  ) {
    return `For local testing, start the demo target with "node vulnerable-app.js" inside demo-target and scan http://localhost:4001 from AutoReconX.`;
  }

  if (text.includes("summarize") || text.includes("summary")) {
    if (!findings.length) {
      return `The scan for ${targetUrl || "the provided target"} completed successfully and returned 0 findings. That usually means the target was unavailable, the wrong URL was used, or the current payload checks did not detect any supported issues.`;
    }
    return `The scan found ${findings.length} issue(s). Review the endpoints, payloads, snippets, and severities, then prioritize the highest-severity items first.`;
  }

  if (text.includes("remed") || text.includes("fix")) {
    if (!findings.length) {
      return `There are no findings to remediate yet. First verify the demo target is running and rescan http://localhost:4001.`;
    }
    return `Start by validating input, encoding output safely, and adding stricter server-side checks around the affected endpoints. Then rerun the scan to confirm the issue is resolved.`;
  }

  if (text.includes("explain")) {
    if (!findings.length) {
      return `This scan currently has no findings to explain. Try scanning the local demo target at http://localhost:4001 after starting it from the demo-target folder.`;
    }
    const first = findings[0];
    return `This finding suggests potentially unsafe behavior at ${first.endpoint || "an endpoint"}. Focus on how input is handled, whether output is reflected unsafely, and whether validation or sanitization is missing.`;
  }

  return `I can help explain findings, summarize scans, suggest remediation, or troubleshoot the local demo target. Try asking: "Why did I get 0 findings?" or "Summarize this scan."`;
}

function buildReportDraft(findings = [], targetUrl = "", notes = "") {
  const first = findings[0] || {};
  const vulnerability = first.vulnerability || "Potential web vulnerability";
  const endpoint = first.endpoint || targetUrl || "[affected endpoint]";
  const payload = first.payload || "[observed input]";
  const snippet = first.responseSnippet || "[relevant response snippet]";
  const severity = first.severity || "Medium";

  return `## Title
${vulnerability} in ${endpoint}

## Weakness
${vulnerability}

## Severity
Estimated severity: ${severity}

## Summary
A potential ${vulnerability.toLowerCase()} was identified in ${endpoint} during testing of ${targetUrl || "the target application"}. The behavior suggests the application may process unsafe input in a way that could expose users or backend functionality to unintended risk.

## Steps To Reproduce
1. Start AutoReconX locally and ensure the demo target or tested application is reachable.
2. Enter the target URL: ${targetUrl || "[target URL]"}.
3. Run a scan and wait for completion.
4. Review the finding associated with endpoint: ${endpoint}.
5. Observe the payload and response behavior shown in the results table.

## Supporting Material / References
- Target URL: ${targetUrl || "[target URL]"}
- Endpoint: ${endpoint}
- Payload observed: ${payload}
- Response snippet: ${snippet}
- Additional notes: ${notes || "[add screenshots, request/response logs, or screen recordings here]"}

## Impact
An attacker may be able to exploit unsafe input handling at ${endpoint}, depending on how the affected code path is used in production. The security impact could include unauthorized client-side script execution, input reflection, or other unsafe processing behavior, depending on the exact root cause and surrounding controls.

## Remediation Notes
Validate and sanitize untrusted input on the server side, apply context-appropriate output encoding, and retest the affected endpoint after fixes are deployed.`;
}

app.post("/api/scan", async (req, res) => {
  try {
    const { target } = req.body;

    console.log("Incoming scan target:", target);

    if (!target) {
      return res.status(400).json({ error: "Target URL is required" });
    }

    const scanId = Date.now().toString();

    scans.set(scanId, {
      progress: { current: 0, total: 1, percent: 0 },
      results: [],
      status: "running",
      target
    });

    res.json({ scanId });

    const endpoints = await crawl(target);
    console.log("Crawled endpoints:", endpoints);

    const findings = await runScans(endpoints, target, (progress) => {
      const state = scans.get(scanId);
      if (state) {
        state.progress = progress;
      }
    });

    console.log("Scan findings:", findings);

    scans.set(scanId, {
      progress: { current: 100, total: 100, percent: 100 },
      results: formatFindings(findings),
      status: "done",
      target
    });
  } catch (err) {
    console.error("Scan route error:", err);

    if (req.body && req.body.target) {
      const scanId = Date.now().toString();
      scans.set(scanId, {
        progress: { current: 0, total: 1, percent: 0 },
        results: [],
        status: "error",
        error: err.message,
        target: req.body.target
      });
    }

    if (!res.headersSent) {
      res.status(500).json({ error: err.message || "Internal server error" });
    }
  }
});

app.post("/api/chat", async (req, res) => {
  try {
    const { message, findings, targetUrl } = req.body || {};

    if (!message || typeof message !== "string") {
      return res.status(400).json({ reply: "Please enter a message." });
    }

    const safeFindings = Array.isArray(findings) ? findings.slice(0, 10) : [];
    const apiKey = process.env.OPENAI_API_KEY;

    if (!apiKey) {
      return res.json({
        reply: buildFallbackReply(message, safeFindings, targetUrl),
        mode: "fallback"
      });
    }

    const systemPrompt = `
You are AutoReconX Assistant, a defensive security helper for a local demo scanner.
Only help with:
- explaining findings in plain language
- summarizing scans
- suggesting remediation and defensive fixes
- troubleshooting local demo setup
Never provide exploit payloads, attack instructions, bypasses, or offensive steps.
Keep answers concise, practical, and safe.
    `.trim();

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        temperature: 0.2,
        messages: [
          { role: "system", content: systemPrompt },
          {
            role: "user",
            content: `Context: ${JSON.stringify({
              targetUrl: targetUrl || "",
              findings: safeFindings
            })}`
          },
          { role: "user", content: message }
        ]
      })
    });

    if (!response.ok) {
      return res.json({
        reply: buildFallbackReply(message, safeFindings, targetUrl),
        mode: "fallback"
      });
    }

    const data = await response.json();
    const reply =
      data?.choices?.[0]?.message?.content ||
      buildFallbackReply(message, safeFindings, targetUrl);

    res.json({ reply, mode: "llm" });
  } catch (err) {
    console.error("Chat route error:", err);
    res.json({
      reply: "The assistant is temporarily unavailable. Try asking about scan summary, remediation, or the local demo target.",
      mode: "fallback"
    });
  }
});

app.post("/api/report-draft", async (req, res) => {
  try {
    const { findings, targetUrl, notes } = req.body || {};
    const safeFindings = Array.isArray(findings) ? findings.slice(0, 10) : [];
    const apiKey = process.env.OPENAI_API_KEY;

    if (!apiKey) {
      return res.json({
        report: buildReportDraft(safeFindings, targetUrl, notes),
        mode: "fallback"
      });
    }

    const systemPrompt = `
You are AutoReconX Report Assistant.
Generate a professional vulnerability report draft in a HackerOne-style format.
Focus on:
- clear title
- weakness type
- severity estimate
- concise summary
- reproducible validation steps
- supporting material placeholders
- realistic impact
- remediation notes
Do not invent proof that is not present.
Do not provide exploit payloads or offensive instructions.
Use cautious language such as "potential", "observed", and "may" when certainty is limited.
Return Markdown only.
    `.trim();

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        temperature: 0.2,
        messages: [
          { role: "system", content: systemPrompt },
          {
            role: "user",
            content: `Generate a vulnerability report draft from this context: ${JSON.stringify({
              targetUrl: targetUrl || "",
              findings: safeFindings,
              notes: notes || ""
            })}`
          }
        ]
      })
    });

    if (!response.ok) {
      return res.json({
        report: buildReportDraft(safeFindings, targetUrl, notes),
        mode: "fallback"
      });
    }

    const data = await response.json();
    const report =
      data?.choices?.[0]?.message?.content ||
      buildReportDraft(safeFindings, targetUrl, notes);

    res.json({ report, mode: "llm" });
  } catch (err) {
    console.error("Report draft route error:", err);
    res.json({
      report: buildReportDraft([], "", ""),
      mode: "fallback"
    });
  }
});

app.get("/api/progress/:scanId", (req, res) => {
  const state = scans.get(req.params.scanId);
  res.json(state || { status: "unknown" });
});

app.get("/api/report/:scanId", (req, res) => {
  const state = scans.get(req.params.scanId);
  res.json(state || { status: "unknown" });
});

app.get("/api/export/:scanId", (req, res) => {
  const state = scans.get(req.params.scanId);

  if (!state) {
    return res.status(404).json({ error: "Not found" });
  }

  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=report-${req.params.scanId}.json`
  );

  res.send(exportJson(state.results));
});

app.get("/api/debug-crawl", async (req, res) => {
  try {
    const target = req.query.target;

    if (!target) {
      return res.status(400).json({ error: "target is required" });
    }

    const endpoints = await crawl(target);
    res.json({ count: endpoints.length, endpoints });
  } catch (err) {
    console.error("Debug crawl error:", err);
    res.status(500).json({ error: err.message || "Debug crawl failed" });
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled server error:", err);
  res.status(500).json({ error: err.message || "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`AutoReconX running on port ${PORT}`);
});