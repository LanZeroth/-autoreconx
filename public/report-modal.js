window.AutoReconXReportModal = (() => {
  function escapeHtml(str = "") {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function markdownToHtml(md = "") {
    return escapeHtml(md)
      .replace(/^### (.*$)/gim, "<h3>$1</h3>")
      .replace(/^## (.*$)/gim, "<h2>$1</h2>")
      .replace(/^# (.*$)/gim, "<h1>$1</h1>")
      .replace(/^\- (.*$)/gim, "<li>$1</li>")
      .replace(/^(\d+)\. (.*$)/gim, "<li>$2</li>")
      .replace(/```([a-z]*)\n([\s\S]*?)```/gim, "<pre><code>$2</code></pre>")
      .replace(/\n{2,}/g, "</p><p>")
      .replace(/^(?!<h|<li|<pre)(.+)$/gim, "<p>$1</p>")
      .replace(/(<li>.*<\/li>)/gims, "<ul>$1</ul>");
  }

  function copyText(text) {
    return navigator.clipboard.writeText(text);
  }

  function downloadFile(filename, content, type = "text/markdown") {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function createModal() {
    const modal = document.createElement("div");
    modal.className = "arx-report-modal";
    modal.innerHTML = `
      <div class="arx-report-dialog">
        <div class="arx-report-header">
          <div>
            <h2>Generated Report</h2>
            <p class="arx-report-subtitle">Switch between pentest and bug bounty formats.</p>
          </div>
          <button class="arx-close-btn" aria-label="Close">×</button>
        </div>

        <div class="arx-report-tabs">
          <button class="arx-tab active" data-tab="pentest">Pentest Report</button>
          <button class="arx-tab" data-tab="h1">HackerOne Draft</button>
        </div>

        <div class="arx-report-actions">
          <button class="arx-action-btn" data-action="copy">Copy Markdown</button>
          <button class="arx-action-btn" data-action="download-md">Download .md</button>
          <button class="arx-action-btn" data-action="download-html">Download .html</button>
        </div>

        <div class="arx-report-body">
          <div class="arx-report-panel active" data-panel="pentest"></div>
          <div class="arx-report-panel" data-panel="h1"></div>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    return modal;
  }

  function open(reportData) {
    const modal = createModal();
    const pentestPanel = modal.querySelector('[data-panel="pentest"]');
    const h1Panel = modal.querySelector('[data-panel="h1"]');
    const tabs = modal.querySelectorAll(".arx-tab");

    pentestPanel.innerHTML = markdownToHtml(reportData.pentestMarkdown);
    h1Panel.innerHTML = markdownToHtml(reportData.hackeroneMarkdown);

    tabs.forEach(tab => {
      tab.addEventListener("click", () => {
        tabs.forEach(t => t.classList.remove("active"));
        modal.querySelectorAll(".arx-report-panel").forEach(p => p.classList.remove("active"));
        tab.classList.add("active");
        modal.querySelector(`[data-panel="${tab.dataset.tab}"]`).classList.add("active");
      });
    });

    modal.querySelector(".arx-close-btn").addEventListener("click", () => modal.remove());

    modal.querySelector('[data-action="copy"]').addEventListener("click", async () => {
      const activeTab = modal.querySelector(".arx-tab.active").dataset.tab;
      const content = activeTab === "pentest" ? reportData.pentestMarkdown : reportData.hackeroneMarkdown;
      await copyText(content);
    });

    modal.querySelector('[data-action="download-md"]').addEventListener("click", () => {
      const activeTab = modal.querySelector(".arx-tab.active").dataset.tab;
      const content = activeTab === "pentest" ? reportData.pentestMarkdown : reportData.hackeroneMarkdown;
      const filename = activeTab === "pentest" ? "pentest-report.md" : "hackerone-draft.md";
      downloadFile(filename, content, "text/markdown");
    });

    modal.querySelector('[data-action="download-html"]').addEventListener("click", () => {
      const activeTab = modal.querySelector(".arx-tab.active").dataset.tab;
      const md = activeTab === "pentest" ? reportData.pentestMarkdown : reportData.hackeroneMarkdown;
      const html = `
        <html>
          <head>
            <meta charset="UTF-8" />
            <title>AutoReconX Report</title>
            <style>
              body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; line-height: 1.6; color: #111; }
              pre { background: #111; color: #eee; padding: 16px; overflow: auto; border-radius: 8px; }
              h1, h2, h3 { color: #0f172a; }
            </style>
          </head>
          <body>${markdownToHtml(md)}</body>
        </html>
      `;
      const filename = activeTab === "pentest" ? "pentest-report.html" : "hackerone-draft.html";
      downloadFile(filename, html, "text/html");
    });

    modal.addEventListener("click", e => {
      if (e.target === modal) modal.remove();
    });
  }

  return { open };
})();