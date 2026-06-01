const express = require("express");
const Ioc = require("../models/Ioc");
const { requireAuth, requireAdmin } = require("../middleware/auth");
const { detectIocType, normalizeIocValue } = require("../utils/detectIocType");
const writeAuditLog = require("../utils/audit");

const router = express.Router();

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
        status: iocRecord ? "known_threat" : "unknown",
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
