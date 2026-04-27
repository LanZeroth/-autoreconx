/**
 * AutoReconX — Improved Vulnerable Demo Target
 *
 * Changes from v1:
 *   IDOR:  /profile?id=2 now returns DIFFERENT data than id=1
 *          (role: admin visible) — scanner's baseline comparison will trigger
 *
 *   XSS:   Explicit Content-Type: text/html header so scanner
 *          confirms HTML context. Added /query param for second XSS hit.
 *
 *   SSRF:  Now handles broader payload set:
 *          127.0.0.1, ::1, 0.0.0.0, and IPv6 loopback all resolve to internal.
 *          Returns structured JSON so the response body has clear signals.
 *
 *   Mass:  /register and /user both echo ALL received fields back —
 *          scanner's echo-field detection will confirm mass assignment.
 *          /update route added for PATCH testing.
 *
 * ⚠️ LOCAL DEMO ONLY — never expose this to the internet.
 */

const express = require("express");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Simulated user database ────────────────────────────────────
const USERS = {
  1: { id: 1, name: "Alice",   email: "alice@example.com",   role: "user",  balance: 1200 },
  2: { id: 2, name: "Bob",     email: "bob@example.com",     role: "admin", balance: 99999, apiKey: "sk-prod-abc123" },
  3: { id: 3, name: "Charlie", email: "charlie@example.com", role: "user",  balance: 340 },
};

// ── Homepage ───────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(`
    <html>
      <head><title>Demo Target</title></head>
      <body>
        <h1>VulnApp — Demo Target for AutoReconX</h1>
        <p>Intentionally vulnerable local app. Do not expose to internet.</p>
        <h2>Navigation</h2>
        <ul>
          <li><a href="/profile?id=1">Profile (user)</a></li>
          <li><a href="/profile?id=2">Profile (admin — IDOR target)</a></li>
          <li><a href="/search?q=hello">Search (XSS target)</a></li>
          <li><a href="/query?q=world">Query (XSS target)</a></li>
          <li><a href="/fetch?url=http://example.com">Fetch (SSRF target)</a></li>
        </ul>
        <h2>Forms</h2>
        <form method="POST" action="/register">
          <input name="name"  value="guest" />
          <input name="email" value="guest@example.com" />
          <button>Register (Mass Assignment target)</button>
        </form>
      </body>
    </html>
  `);
});

// ── /profile — IDOR vulnerability ─────────────────────────────
// id=1 → normal user data
// id=2 → admin with sensitive fields (apiKey, balance: 99999)
// The DIFFERENCE in response body is what the scanner detects.
app.get("/profile", (req, res) => {
  const id   = parseInt(req.query.id, 10);
  const user = USERS[id];

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // No auth check — any caller can access any user's profile
  res.setHeader("Content-Type", "application/json");
  res.json(user);
});

// ── /search — Reflected XSS ────────────────────────────────────
// Param q is reflected into HTML response without sanitization.
// Content-Type is explicitly text/html so scanner confirms context.
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  // 🚨 VULN: q is interpolated directly — no escaping
  res.send(`
    <html>
      <head><title>Search</title></head>
      <body>
        <h2>Search Results</h2>
        <p>Showing results for: ${q}</p>
        <p>No matching records found.</p>
      </body>
    </html>
  `);
});

// ── /query — Second XSS endpoint (different param name) ────────
app.get("/query", (req, res) => {
  const q = req.query.q || "";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
    <html>
      <body>
        <div class="results">
          <span>Query: ${q}</span>
        </div>
      </body>
    </html>
  `);
});

// ── /fetch — SSRF vulnerability ────────────────────────────────
// Accepts a ?url= param and simulates a server-side fetch.
// Recognizes a broad set of internal address payloads.
app.get("/fetch", (req, res) => {
  const targetUrl = req.query.url || "";

  const isInternal =
    targetUrl.includes("127.0.0.1") ||
    targetUrl.includes("localhost")  ||
    targetUrl.includes("0.0.0.0")    ||
    targetUrl.includes("[::1]")      ||
    targetUrl.includes("::1")        ||
    targetUrl.includes("169.254")    ||
    targetUrl.includes("192.168")    ||
    targetUrl.includes("10.0")       ||
    targetUrl.includes("/internal");

  if (isInternal) {
    // 🚨 VULN: Returns internal resource content
    return res.json({
      fetchedUrl: targetUrl,
      status: 200,
      // Realistic internal response — contains SSRF signals the scanner looks for
      body: "internal-demo-resource",
      metadata: {
        "ami-id":        "ami-0abc12345",
        "instance-id":   "i-0deadbeef",
        "local-hostname": "ip-10-0-0-1.ec2.internal"
      }
    });
  }

  res.json({
    fetchedUrl: targetUrl,
    status: 200,
    body: "External content fetched successfully"
  });
});

// ── /register — Mass Assignment (POST) ────────────────────────
// Spreads ALL received body fields onto the user object and echoes back.
// Scanner sends { name, email, isAdmin: true, role: "admin" }
// and checks if those fields appear in the response.
app.post("/register", (req, res) => {
  // 🚨 VULN: No field whitelist — spreads entire req.body
  const newUser = {
    id: Math.floor(Math.random() * 9000) + 1000,
    ...req.body   // Attacker controls ALL fields here
  };
  res.status(201).json(newUser);
});

// ── /user — Mass Assignment (PUT) ─────────────────────────────
app.put("/user", (req, res) => {
  const base = { id: 1, name: "Alice", email: "alice@example.com", role: "user" };
  // 🚨 VULN: Merges all fields without whitelist
  const updated = { ...base, ...req.body };
  res.json(updated);
});

// ── /profile — Mass Assignment (POST) ─────────────────────────
app.post("/profile", (req, res) => {
  const base = { id: 2, name: "Bob", email: "bob@example.com" };
  const updated = { ...base, ...req.body };
  res.json(updated);
});

// ── /account — Mass Assignment (PUT) ──────────────────────────
app.put("/account", (req, res) => {
  const base = { id: 1, tier: "free", verified: false };
  const updated = { ...base, ...req.body };
  res.json(updated);
});

// ── /internal — Simulated internal endpoint ────────────────────
// Reachable by SSRF, not linked from main nav
app.get("/internal", (req, res) => {
  res.json({
    message:  "internal-demo-resource",
    secret:   "db-password-from-env",
    internal: true
  });
});

app.listen(4001, () => {
  console.log(`
  ⚠️  Demo target running at http://localhost:4001
  ⚠️  Intentionally vulnerable — local testing only!

  Endpoints:
    GET  /profile?id=1    (user)
    GET  /profile?id=2    (admin — IDOR)
    GET  /search?q=test   (XSS)
    GET  /query?q=test    (XSS)
    GET  /fetch?url=...   (SSRF)
    POST /register        (Mass Assignment)
    PUT  /user            (Mass Assignment)
  `);
});