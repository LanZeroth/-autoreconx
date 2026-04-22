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
      status: "running"
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
      status: "done"
    });
  } catch (err) {
    console.error("Scan route error:", err);

    if (req.body && req.body.target) {
      const scanId = Date.now().toString();
      scans.set(scanId, {
        progress: { current: 0, total: 1, percent: 0 },
        results: [],
        status: "error",
        error: err.message
      });
    }

    if (!res.headersSent) {
      res.status(500).json({ error: err.message || "Internal server error" });
    }
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