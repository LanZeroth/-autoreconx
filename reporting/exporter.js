function exportJson(data) {
  return JSON.stringify(data, null, 2);
}

function markdownToHtml(md = "") {
  return String(md)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/^### (.*$)/gim, "<h3>$1</h3>")
    .replace(/^## (.*$)/gim, "<h2>$1</h2>")
    .replace(/^# (.*$)/gim, "<h1>$1</h1>")
    .replace(/^\- (.*$)/gim, ">$1</li>")
    .replace(/^(\d+)\. (.*$)/gim, ">$2</li>")
    .replace(/\n{2,}/g, "</p><p>")
    .replace(/^(?!<h|)(.+)$/gim, "<p>$1</p>")
    .replace(/(>.*<\/li>)/gims, "<ul>$1</ul>");
}

function exportMarkdown(text = "") {
  return text;
}

function exportHtml(title = "AutoReconX Report", markdown = "") {
  const body = markdownToHtml(markdown);
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; line-height: 1.6; color: #111827; padding: 0 16px; }
    h1, h2, h3 { color: #0f172a; }
    ul { padding-left: 20px; }
    p { margin: 0 0 12px; }
  </style>
</head>
<body>
${body}
</body>
</html>
`;
}

module.exports = {
  exportJson,
  exportMarkdown,
  exportHtml
};