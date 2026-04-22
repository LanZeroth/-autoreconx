function exportJson(report) {
  return JSON.stringify(report, null, 2);
}

module.exports = { exportJson };