let currentScanId = null;
let poller = null;

const scanBtn = document.getElementById("scanBtn");
const exportBtn = document.getElementById("exportBtn");
const targetInput = document.getElementById("targetInput");
const progressFill = document.getElementById("progressFill");
const progressText = document.getElementById("progressText");
const resultsBody = document.getElementById("resultsBody");
const findingCount = document.getElementById("findingCount");

scanBtn.addEventListener("click", async () => {
  const target = targetInput.value.trim();

  if (!target) {
    alert("Please enter a target URL");
    return;
  }

  resetUI();
  scanBtn.disabled = true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ target })
    });

    const data = await res.json();
    currentScanId = data.scanId;
    startPolling();
  } catch (err) {
    progressText.textContent = "Error starting scan";
    scanBtn.disabled = false;
    console.error(err);
  }
});

exportBtn.addEventListener("click", () => {
  if (!currentScanId) return;
  window.open(`/api/export/${currentScanId}`, "_blank");
});

function resetUI() {
  exportBtn.disabled = true;
  progressFill.style.width = "0%";
  progressText.textContent = "Starting...";
  findingCount.textContent = "0 results";
  resultsBody.innerHTML = `<tr><td colspan="5" class="empty">Scan in progress...</td></tr>`;
}

function startPolling() {
  if (poller) clearInterval(poller);

  poller = setInterval(async () => {
    try {
      const res = await fetch(`/api/progress/${currentScanId}`);
      const data = await res.json();

      const percent = data.progress?.percent || 0;
      progressFill.style.width = `${percent}%`;
      progressText.textContent = `${data.status || "running"} - ${percent}%`;

      if (data.status === "done") {
        clearInterval(poller);
        renderResults(data.results || []);
        exportBtn.disabled = false;
        scanBtn.disabled = false;
      }

      if (data.status === "error") {
        clearInterval(poller);
        progressText.textContent = `Error: ${data.error || "unknown error"}`;
        scanBtn.disabled = false;
      }
    } catch (err) {
      clearInterval(poller);
      progressText.textContent = "Error while polling";
      scanBtn.disabled = false;
      console.error(err);
    }
  }, 1000);
}

function renderResults(results) {
  findingCount.textContent = `${results.length} result${results.length === 1 ? "" : "s"}`;

  if (!results.length) {
    resultsBody.innerHTML = `<tr><td colspan="5" class="empty">No findings detected.</td></tr>`;
    return;
  }

  resultsBody.innerHTML = "";

  for (const item of results) {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${escapeHtml(item.vulnerability || "")}</td>
      <td>${escapeHtml(item.endpoint || "")}</td>
      <td>${escapeHtml(item.payload || "")}</td>
      <td>${escapeHtml(item.responseSnippet || "")}</td>
      <td class="${String(item.severity || "").toLowerCase()}">${escapeHtml(item.severity || "")}</td>
    `;

    resultsBody.appendChild(row);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}