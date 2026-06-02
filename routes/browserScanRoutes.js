const express = require("express");
const Ioc = require("../models/Ioc");
const { requireAuth, requireAdmin } = require("../middleware/auth");
const { detectIocType, normalizeIocValue } = require("../utils/detectIocType");
const writeAuditLog = require("../utils/audit");

const router = express.Router();

const SAFE_DOMAINS = new Set([
  "localhost", "example.com", "example.org", "test.com",
  "google.com", "googleapis.com", "gstatic.com", "youtube.com",
  "cloudflare.com", "cloudfront.net", "amazonaws.com",
  "microsoft.com", "windows.com", "apple.com", "icloud.com"
]);

const SUSPICIOUS_URL_PATH = /(?:^|\/)(?:admin|dashboard|login|manage|panel|secure|phpmyadmin|wp-admin|config|\.env|shell|console|cgi-bin)/i;

function classifyIoc(value, iocType, iocRecord) {
  if (iocRecord) return "known_threat";

  if (iocType === "URL") {
    try {
      const url = new URL(value);
      const host = url.hostname.toLowerCase().replace(/^www\./, "");
      if (SUSPICIOUS_URL_PATH.test(url.pathname + url.search + url.hash)) {
        return "vulnerable";
      }
      if (SAFE_DOMAINS.has(host)) {
        return "safe";
      }
    } catch (__) {
      return "unknown";
    }
  }

  if (iocType === "Domain") {
    const host = value.toLowerCase().replace(/^www\./, "");
    if (SAFE_DOMAINS.has(host)) {
      return "safe";
    }
  }

  return "unknown";
}

// ─── Render the browser scan page ────────────────────────────────────────────
router.get("/browser-scan", requireAuth, (req, res) => {
  res.render("iocs/browser-scan", {
    title: "Browser IoC Scanner"
  });
});

// ─── API: check a batch of extracted indicators against the DB ───────────────
// Accepts: { indicators: ["1.2.3.4", "evil.com", ...] }
// Returns: array of { value, iocType, status, iocRecord | null }
router.post("/browser-detect", requireAuth, async (req, res, next) => {
  try {
    const raw = req.body.indicators;
    if (!Array.isArray(raw) || raw.length === 0) {
      return res.json({ results: [] });
    }

    // Deduplicate and normalise
    const normalized = [...new Set(raw.map(normalizeIocValue).filter(Boolean))];

    // Fetch all matching IOCs in one query
    const found = await Ioc.find({ value: { $in: normalized } }).lean();
    const foundMap = Object.fromEntries(found.map((d) => [d.value, d]));

    const results = normalized.map((value) => {
      const iocType = detectIocType(value);
      const iocRecord = foundMap[value] || null;
      return {
        value,
        iocType,
        status: classifyIoc(value, iocType, iocRecord),
        iocRecord
      };
    });

    await writeAuditLog(
      req.session.user,
      "BROWSER_SCAN",
      `Scanned ${normalized.length} indicator(s) from browser; ${found.length} matched`
    );

    return res.json({ results });
  } catch (err) {
    next(err);
  }
});

// ─── API: save a detected indicator to the repository ────────────────────────
// Accepts: { value, iocType, threatType, severity, confidence, source, description, tags }
router.post("/browser-save", requireAdmin, async (req, res, next) => {
  try {
    const value = normalizeIocValue(req.body.value);
    if (!value) return res.status(400).json({ error: "IoC value is required." });

    const allowed = ["IP", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email", "Unknown"];
    const iocType =
      allowed.includes(req.body.iocType) ? req.body.iocType : detectIocType(value);

    const severities = ["Low", "Medium", "High", "Critical"];
    const severity = severities.includes(req.body.severity) ? req.body.severity : "Medium";

    const tags = Array.isArray(req.body.tags)
      ? req.body.tags.map(String)
      : String(req.body.tags || "").split(",").map((t) => t.trim()).filter(Boolean);

    const doc = {
      value,
      iocType,
      threatType: String(req.body.threatType || "Browser-Detected Threat").trim(),
      severity,
      confidence: Math.min(100, Math.max(0, Number(req.body.confidence) || 70)),
      source: String(req.body.source || "Browser Scanner").trim(),
      description: String(req.body.description || "").trim(),
      tags,
      createdBy: req.session.user.id
    };

    const ioc = await Ioc.findOneAndUpdate(
      { value },
      { $set: doc },
      { upsert: true, new: true, runValidators: true }
    );

    await writeAuditLog(
      req.session.user,
      "BROWSER_SAVE",
      `Saved browser-detected IoC: ${value} [${iocType}] severity=${severity}`
    );

    return res.json({ success: true, ioc });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: "IoC already exists in the repository." });
    }
    next(err);
  }
});

module.exports = router;
