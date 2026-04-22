function normalizeUrl(base, candidate) {
  try {
    return new URL(candidate, base).toString();
  } catch {
    return null;
  }
}

function sameOrigin(root, target) {
  try {
    return new URL(root).origin === new URL(target).origin;
  } catch {
    return false;
  }
}

module.exports = { normalizeUrl, sameOrigin };