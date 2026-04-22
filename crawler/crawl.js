const axios = require("axios");
const cheerio = require("cheerio");
const { normalizeUrl, sameOrigin } = require("./extractors");

async function crawl(startUrl) {
  const visited = new Set();
  const queue = [startUrl];
  const endpoints = [];

  while (queue.length && visited.size < 20) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);

    try {
      const res = await axios.get(url, { timeout: 5000 });
      const $ = cheerio.load(res.data);

      endpoints.push({
        type: "page",
        method: "GET",
        url
      });

      $("a[href]").each((_, el) => {
        const href = $(el).attr("href");
        const absolute = normalizeUrl(url, href);

        if (absolute && sameOrigin(startUrl, absolute)) {
          endpoints.push({
            type: "link",
            method: "GET",
            url: absolute
          });

          if (!visited.has(absolute)) {
            queue.push(absolute);
          }
        }
      });

      $("form").each((_, el) => {
        const action = $(el).attr("action") || url;
        const method = (($(el).attr("method") || "GET")).toUpperCase();
        const absolute = normalizeUrl(url, action);

        const inputs = [];
        $(el).find("input, textarea, select").each((__, input) => {
          const name = $(input).attr("name");
          if (name) inputs.push(name);
        });

        endpoints.push({
          type: "form",
          method,
          url: absolute,
          params: inputs
        });
      });
    } catch (err) {
      endpoints.push({
        type: "error",
        method: "GET",
        url,
        error: err.message
      });
    }
  }

  const seeded = [
    `${startUrl}/profile?id=1`,
    `${startUrl}/search?q=test`,
    `${startUrl}/fetch?url=http://example.com`,
    `${startUrl}/register`,
    `${startUrl}/user`
  ];

  for (const url of seeded) {
    endpoints.push({
      type: "seeded",
      method: url.endsWith("/register") ? "POST" : url.endsWith("/user") ? "PUT" : "GET",
      url
    });
  }

  return dedupeEndpoints(endpoints);
}

function dedupeEndpoints(endpoints) {
  const seen = new Set();

  return endpoints.filter((item) => {
    const key = `${item.method}:${item.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { crawl };