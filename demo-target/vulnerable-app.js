const express = require("express");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const users = [
  { id: 1, name: "Alice", role: "user" },
  { id: 2, name: "Bob", role: "admin" }
];

app.get("/", (req, res) => {
  res.send(`
    <html>
      <head><title>Demo Target</title></head>
      <body>
        <h1>Demo Target</h1>
        <p>Intentionally vulnerable local app for AutoReconX demos.</p>

        <ul>
          <li><a href="/profile?id=1">Profile 1</a></li>
          <li><a href="/profile?id=2">Profile 2</a></li>
          <li><a href="/search?q=test">Search</a></li>
          <li><a href="/fetch?url=http://example.com">Fetch</a></li>
        </ul>

        <form method="POST" action="/register">
          <input name="name" value="guest" />
          <input name="email" value="guest@example.com" />
          <button type="submit">Register</button>
        </form>
      </body>
    </html>
  `);
});

app.get("/profile", (req, res) => {
  const id = Number(req.query.id);
  const user = users.find((u) => u.id === id);

  if (!user) {
    return res.status(404).send("Not found");
  }

  res.send(`
    <html>
      <body>
        <h2>${user.name}</h2>
        <p>User ID: ${user.id}</p>
        <p>Role: ${user.role}</p>
      </body>
    </html>
  `);
});

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`
    <html>
      <body>
        <h2>Results for: ${q}</h2>
        <p>You searched for ${q}</p>
      </body>
    </html>
  `);
});

app.get("/internal", (req, res) => {
  res.send("internal-demo-resource");
});

app.get("/fetch", (req, res) => {
  const url = req.query.url || "";

  if (url.includes("127.0.0.1") || url.includes("localhost")) {
    return res.send("Fetched: internal-demo-resource");
  }

  res.send("Fetched external content");
});

app.post("/register", (req, res) => {
  const user = {
    id: 3,
    ...req.body
  };

  res.json(user);
});

app.put("/user", (req, res) => {
  const updated = {
    id: 1,
    name: req.body.name || "Alice",
    email: req.body.email || "alice@example.com",
    ...req.body
  };

  res.json(updated);
});

app.listen(4001, () => {
  console.log("Demo target running on http://localhost:4001");
});