function normalizeIocValue(value) {
  return String(value || "").trim().toLowerCase();
}

function detectIocType(value) {
  const input = normalizeIocValue(value);

  if (!input) return "Unknown";

  if (/^https?:\/\//i.test(input)) return "URL";
  if (/^[a-f0-9]{32}$/i.test(input)) return "MD5";
  if (/^[a-f0-9]{40}$/i.test(input)) return "SHA1";
  if (/^[a-f0-9]{64}$/i.test(input)) return "SHA256";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(input)) return "Email";

  const ipPattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (ipPattern.test(input)) return "IP";

  const domainPattern = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
  if (domainPattern.test(input)) return "Domain";

  return "Unknown";
}

module.exports = {
  detectIocType,
  normalizeIocValue
};
