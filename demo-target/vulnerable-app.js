const express = require("express");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const USERS = {
  1: { id: 1, name: "Alice", email: "alice@example.com", role: "user", balance: 1200 },
  2: { id: 2, name: "Bob", email: "bob@example.com", role: "admin", balance: 99999, apiKey: "sk-prod-abc123" },
  3: { id: 3, name: "Charlie", email: "charlie@example.com", role: "user", balance: 340 }
};

app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VulnApp Demo Target</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px;
    }
    .hero {
      margin-bottom: 20px;
    }
    .hero h1 {
      margin: 0 0 8px;
      font-size: 32px;
    }
    .hero p {
      margin: 0;
      color: #94a3b8;
      line-height: 1.6;
    }
    .warning {
      margin-top: 12px;
      padding: 12px 14px;
      border-radius: 12px;
      background: #3f1d1d;
      border: 1px solid #7f1d1d;
      color: #fecaca;
      font-size: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 14px;
      padding: 16px;
    }
    .card h2 {
      margin-top: 0;
      margin-bottom: 8px;
      font-size: 20px;
    }
    .card p {
      margin-top: 0;
      color: #94a3b8;
      line-height: 1.5;
    }
    label {
      display: block;
      margin: 10px 0 6px;
      font-weight: bold;
      font-size: 14px;
    }
    input, textarea, select {
      width: 100%;
      padding: 12px;
      border-radius: 10px;
      border: 1px solid #475569;
      background: #0b1220;
      color: #e2e8f0;
      font: inherit;
    }
    textarea {
      min-height: 120px;
      resize: vertical;
    }
    .row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 12px;
    }
    button {
      padding: 12px 14px;
      border: none;
      border-radius: 10px;
      background: #38bdf8;
      color: #082f49;
      font-weight: bold;
      cursor: pointer;
    }
    button.secondary {
      background: #1e40af;
      color: #dbeafe;
    }
    button.success {
      background: #22c55e;
      color: #052e16;
    }
    button:hover {
      opacity: 0.95;
    }
    .code, pre {
      background: #0b1220;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 14px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .muted {
      color: #94a3b8;
      font-size: 14px;
    }
    .pill {
      display: inline-block;
      margin-right: 8px;
      margin-bottom: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      background: #1d4ed8;
      color: #dbeafe;
      font-size: 12px;
      font-weight: bold;
    }
    .footer-note {
      margin-top: 18px;
      color: #94a3b8;
      font-size: 13px;
      line-height: 1.6;
    }
    @media (max-width: 700px) {
      .container { padding: 16px; }
      .hero h1 { font-size: 28px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="hero">
      <h1>VulnApp Demo Target</h1>
      <p>Single-file local demo application for AutoReconX testing.</p>
      <div class="warning">
        Local learning environment only. Do not expose this app to the internet or use it outside controlled testing.
      </div>
    </header>

    <section class="card">
      <h2>Available Routes</h2>
      <div class="pill">GET /profile?id=1</div>
      <div class="pill">GET /profile?id=2</div>
      <div class="pill">GET /search?q=hello</div>
      <div class="pill">GET /query?q=world</div>
      <div class="pill">GET /fetch?url=http://example.com</div>
      <div class="pill">POST /register</div>
      <div class="pill">PUT /user</div>
      <div class="pill">POST /profile</div>
      <div class="pill">PUT /account</div>
      <div class="pill">GET /internal</div>
      <p class="footer-note">
        Use the controls below to interact with the local demo target and inspect the raw response.
      </p>
    </section>

    <div class="grid">
      <section class="card">
        <h2>Profile Viewer</h2>
        <p>Fetch a user profile by ID and inspect the JSON response.</p>
        <label for="profileId">Profile ID</label>
        <input id="profileId" type="number" value="1" min="1" />
        <div class="row">
          <button id="loadProfileBtn" type="button">Load Profile</button>
          <button id="loadAdminBtn" type="button" class="secondary">Load Admin Profile</button>
        </div>
      </section>

      <section class="card">
        <h2>Search Page</h2>
        <p>Open the search endpoint in a new tab using a query value.</p>
        <label for="searchQuery">Search Query</label>
        <input id="searchQuery" type="text" value="hello" />
        <div class="row">
          <button id="openSearchBtn" type="button">Open /search</button>
          <button id="openQueryBtn" type="button" class="secondary">Open /query</button>
        </div>
      </section>

      <section class="card">
        <h2>Fetch Tester</h2>
        <p>Send a URL to the fetch route and inspect the JSON response.</p>
        <label for="fetchUrl">URL</label>
        <input id="fetchUrl" type="text" value="http://example.com" />
        <div class="row">
          <button id="fetchBtn" type="button">Send to /fetch</button>
        </div>
      </section>

      <section class="card">
        <h2>Register Form</h2>
        <p>Submit form data to the register route and view the returned JSON.</p>
        <label for="registerName">Name</label>
        <input id="registerName" type="text" value="guest" />
        <label for="registerEmail">Email</label>
        <input id="registerEmail" type="email" value="guest@example.com" />
        <label for="registerExtra">Extra JSON Fields</label>
        <textarea id="registerExtra">{ "role": "admin", "isAdmin": true }</textarea>
        <div class="row">
          <button id="registerBtn" type="button" class="success">POST /register</button>
        </div>
      </section>

      <section class="card">
        <h2>User Update</h2>
        <p>Send JSON data to the update routes and inspect the response.</p>
        <label for="userPayload">PUT /user payload</label>
        <textarea id="userPayload">{ "role": "admin", "tier": "pro" }</textarea>
        <div class="row">
          <button id="putUserBtn" type="button">PUT /user</button>
          <button id="putAccountBtn" type="button" class="secondary">PUT /account</button>
        </div>
      </section>

      <section class="card">
        <h2>Profile Update</h2>
        <p>Send JSON data to POST /profile and inspect the response.</p>
        <label for="profilePayload">POST /profile payload</label>
        <textarea id="profilePayload">{ "role": "admin", "verified": true }</textarea>
        <div class="row">
          <button id="postProfileBtn" type="button">POST /profile</button>
          <button id="internalBtn" type="button" class="secondary">GET /internal</button>
        </div>
      </section>
    </div>

    <section class="card" style="margin-top:16px;">
      <h2>Response Viewer</h2>
      <p class="muted">Raw status and response body from the selected action.</p>
      <pre id="responseBox">No request sent yet.</pre>
    </section>
  </div>

  <script>
    const responseBox = document.getElementById("responseBox");

    function showResponse(status, data) {
      responseBox.textContent = "Status: " + status + "\\n\\n" + (
        typeof data === "string" ? data : JSON.stringify(data, null, 2)
      );
    }

    function safeParseJson(value, fallback = {}) {
      try {
        return JSON.parse(value);
      } catch (err) {
        return fallback;
      }
    }

    async function sendJson(url, method, body) {
      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      let data;
      const contentType = res.headers.get("content-type") || "";

      if (contentType.includes("application/json")) {
        data = await res.json();
      } else {
        data = await res.text();
      }

      showResponse(res.status, data);
    }

    async function sendGet(url) {
      const res = await fetch(url);
      let data;
      const contentType = res.headers.get("content-type") || "";

      if (contentType.includes("application/json")) {
        data = await res.json();
      } else {
        data = await res.text();
      }

      showResponse(res.status, data);
    }

    document.getElementById("loadProfileBtn").addEventListener("click", async () => {
      const id = document.getElementById("profileId").value || "1";
      await sendGet("/profile?id=" + encodeURIComponent(id));
    });

    document.getElementById("loadAdminBtn").addEventListener("click", async () => {
      document.getElementById("profileId").value = "2";
      await sendGet("/profile?id=2");
    });

    document.getElementById("openSearchBtn").addEventListener("click", () => {
      const q = document.getElementById("searchQuery").value || "";
      window.open("/search?q=" + encodeURIComponent(q), "_blank");
    });

    document.getElementById("openQueryBtn").addEventListener("click", () => {
      const q = document.getElementById("searchQuery").value || "";
      window.open("/query?q=" + encodeURIComponent(q), "_blank");
    });

    document.getElementById("fetchBtn").addEventListener("click", async () => {
      const url = document.getElementById("fetchUrl").value || "";
      await sendGet("/fetch?url=" + encodeURIComponent(url));
    });

    document.getElementById("registerBtn").addEventListener("click", async () => {
      const base = {
        name: document.getElementById("registerName").value || "",
        email: document.getElementById("registerEmail").value || ""
      };
      const extra = safeParseJson(document.getElementById("registerExtra").value, {});
      await sendJson("/register", "POST", { ...base, ...extra });
    });

    document.getElementById("putUserBtn").addEventListener("click", async () => {
      const payload = safeParseJson(document.getElementById("userPayload").value, {});
      await sendJson("/user", "PUT", payload);
    });

    document.getElementById("putAccountBtn").addEventListener("click", async () => {
      const payload = safeParseJson(document.getElementById("userPayload").value, {});
      await sendJson("/account", "PUT", payload);
    });

    document.getElementById("postProfileBtn").addEventListener("click", async () => {
      const payload = safeParseJson(document.getElementById("profilePayload").value, {});
      await sendJson("/profile", "POST", payload);
    });

    document.getElementById("internalBtn").addEventListener("click", async () => {
      await sendGet("/internal");
    });
  </script>
</body>
</html>`);
});

app.get("/profile", (req, res) => {
  const id = parseInt(req.query.id, 10);
  const user = USERS[id];

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  res.json(user);
});

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
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

app.get("/fetch", (req, res) => {
  const targetUrl = req.query.url || "";
  const isInternal =
    targetUrl.includes("127.0.0.1") ||
    targetUrl.includes("localhost") ||
    targetUrl.includes("0.0.0.0") ||
    targetUrl.includes("[::1]") ||
    targetUrl.includes("::1") ||
    targetUrl.includes("169.254") ||
    targetUrl.includes("192.168") ||
    targetUrl.includes("10.0") ||
    targetUrl.includes("/internal");

  if (isInternal) {
    return res.json({
      fetchedUrl: targetUrl,
      status: 200,
      body: "internal-demo-resource",
      metadata: {
        "ami-id": "ami-0abc12345",
        "instance-id": "i-0deadbeef",
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

app.post("/register", (req, res) => {
  const newUser = {
    id: Math.floor(Math.random() * 9000) + 1000,
    ...req.body
  };
  res.status(201).json(newUser);
});

app.put("/user", (req, res) => {
  const base = { id: 1, name: "Alice", email: "alice@example.com", role: "user" };
  const updated = { ...base, ...req.body };
  res.json(updated);
});

app.post("/profile", (req, res) => {
  const base = { id: 2, name: "Bob", email: "bob@example.com" };
  const updated = { ...base, ...req.body };
  res.json(updated);
});

app.put("/account", (req, res) => {
  const base = { id: 1, tier: "free", verified: false };
  const updated = { ...base, ...req.body };
  res.json(updated);
});

app.get("/internal", (req, res) => {
  res.json({
    message: "internal-demo-resource",
    secret: "db-password-from-env",
    internal: true
  });
});

app.listen(4001, () => {
  console.log("Demo target running at http://localhost:4001");
});