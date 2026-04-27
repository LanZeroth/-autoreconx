let currentScanId = null;
let poller = null;

window.latestFindings = [];
window.latestTargetUrl = "";

const scanBtn = document.getElementById("scanBtn");
const exportBtn = document.getElementById("exportBtn");
const targetInput = document.getElementById("targetInput");
const progressFill = document.getElementById("progressFill");
const progressText = document.getElementById("progressText");
const resultsBody = document.getElementById("resultsBody");
const findingCount = document.getElementById("findingCount");

const chatForm = document.getElementById("chatForm");
const chatInput = document.getElementById("chatInput");
const chatMessages = document.getElementById("chatMessages");
const chips = document.querySelectorAll(".chip");

const generateReportBtn = document.getElementById("generateReportBtn");
const copyReportBtn = document.getElementById("copyReportBtn");
const reportNotes = document.getElementById("reportNotes");
const reportOutput = document.getElementById("reportOutput");

scanBtn.addEventListener("click", async () => {
  const target = targetInput.value.trim();

  if (!target) {
    alert("Please enter a target URL");
    return;
  }

  resetUI();
  scanBtn.disabled = true;
  window.latestTargetUrl = target;
  window.latestFindings = [];

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

  if (reportOutput) reportOutput.value = "";
  if (copyReportBtn) copyReportBtn.disabled = true;
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
        const results = data.results || [];
        renderResults(results);
        window.latestFindings = results;
        window.latestTargetUrl = data.target || targetInput.value.trim();
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

function appendMessage(role, text) {
  if (!chatMessages) return;

  const el = document.createElement("div");
  el.className = `msg ${role}`;
  el.textContent = text;
  chatMessages.appendChild(el);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

async function sendChatMessage(message) {
  appendMessage("user", message);

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message,
        findings: window.latestFindings || [],
        targetUrl: window.latestTargetUrl || targetInput.value.trim()
      })
    });

    const data = await res.json();
    appendMessage("assistant", data.reply || "No response returned.");
  } catch (err) {
    console.error(err);
    appendMessage("assistant", "Could not reach the assistant. Please try again.");
  }
}

async function generateReportDraft() {
  if (!reportOutput) return;

  reportOutput.value = "Generating report draft...";
  if (copyReportBtn) copyReportBtn.disabled = true;

  try {
    const res = await fetch("/api/report-draft", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        findings: window.latestFindings || [],
        targetUrl: window.latestTargetUrl || targetInput.value.trim(),
        notes: reportNotes ? reportNotes.value.trim() : ""
      })
    });

    const data = await res.json();
    reportOutput.value = data.report || "No report draft returned.";

    if (copyReportBtn && reportOutput.value.trim()) {
      copyReportBtn.disabled = false;
    }
  } catch (err) {
    console.error(err);
    reportOutput.value = "Could not generate report draft. Please try again.";
    if (copyReportBtn) copyReportBtn.disabled = true;
  }
}

async function copyReportToClipboard() {
  if (!reportOutput || !reportOutput.value.trim()) return;

  try {
    await navigator.clipboard.writeText(reportOutput.value);
    copyReportBtn.textContent = "Copied!";
    setTimeout(() => {
      copyReportBtn.textContent = "Copy Report";
    }, 1500);
  } catch (err) {
    console.error(err);
    reportOutput.select();
    document.execCommand("copy");
    copyReportBtn.textContent = "Copied!";
    setTimeout(() => {
      copyReportBtn.textContent = "Copy Report";
    }, 1500);
  }
}

if (chatForm) {
  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = chatInput.value.trim();

    if (!message) return;

    chatInput.value = "";
    await sendChatMessage(message);
  });
}

chips.forEach((chip) => {
  chip.addEventListener("click", async () => {
    const prompt = chip.dataset.prompt;
    if (!prompt) return;
    await sendChatMessage(prompt);
  });
});

if (generateReportBtn) {
  generateReportBtn.addEventListener("click", async () => {
    await generateReportDraft();
  });
}

if (copyReportBtn) {
  copyReportBtn.addEventListener("click", async () => {
    await copyReportToClipboard();
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}