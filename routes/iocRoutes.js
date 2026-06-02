const express = require("express");
const fs = require("fs");
const multer = require("multer");
const csv = require("csv-parser");
const Ioc = require("../models/Ioc");
const { requireAuth, requireAdmin } = require("../middleware/auth");
const { detectIocType, normalizeIocValue } = require("../utils/detectIocType");
const writeAuditLog = require("../utils/audit");
const extractIocs = require("../utils/reportParser"); // New Parser Utility

const router = express.Router();
const upload = multer({ dest: "uploads/" });

function parseTags(tags) {
  if (Array.isArray(tags)) return tags.map((tag) => String(tag).trim()).filter(Boolean);
  return String(tags || "")
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
}

function cleanSeverity(value) {
  const input = String(value || "Medium").trim();
  const allowed = ["Low", "Medium", "High", "Critical"];
  const match = allowed.find((item) => item.toLowerCase() === input.toLowerCase());
  return match || "Medium";
}

function cleanIocType(value, fallbackValue) {
  const input = String(value || "").trim();
  const allowed = ["IP", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email", "Unknown"];
  const match = allowed.find((item) => item.toLowerCase() === input.toLowerCase());
  return match || detectIocType(fallbackValue);
}

// --- NEW ROUTES FOR REPORT PARSING ---
router.get("/parse", requireAdmin, (req, res) => {
  res.render("iocs/parse", {
    title: "Parse Threat Report",
    form: {}
  });
});

router.post("/parse", requireAdmin, async (req, res, next) => {
  try {
    const { reportText, threatType, severity, source, description, tags } = req.body;
    
    if (!reportText) {
      req.session.errorMessage = "Report text is required.";
      return res.redirect("/iocs/parse");
    }

    const extracted = extractIocs(reportText);
    let addedCount = 0;
    let skippedCount = 0;

    const allIocs = [
      ...extracted.ips.map(ip => ({ value: ip, iocType: 'IP' })),
      ...extracted.domains.map(d => ({ value: d, iocType: 'Domain' })),
      ...extracted.hashes.map(h => ({ value: h, iocType: detectIocType(h) }))
    ];

    for (const item of allIocs) {
      const value = normalizeIocValue(item.value);
      if (!value) continue;

      const exists = await Ioc.findOne({ value });
      if (!exists) {
        await Ioc.create({
          value,
          iocType: item.iocType,
          threatType: String(threatType || "Unknown Threat").trim(),
          severity: cleanSeverity(severity),
          confidence: 50,
          source: String(source || "Parsed Report").trim(),
          description: String(description || "").trim(),
          tags: parseTags(tags),
          createdBy: req.session.user.id
        });
        addedCount++;
      } else {
        skippedCount++;
      }
    }

    await writeAuditLog(req.session.user, "REPORT_PARSED", `Parsed text. Added: ${addedCount}, Skipped: ${skippedCount}`);
    req.session.successMessage = `Successfully parsed report. Added ${addedCount} new IoCs (Skipped ${skippedCount} duplicates).`;
    return res.redirect("/iocs");
  } catch (error) {
    next(error);
  }
});
// ------------------------------------

router.get("/search", requireAuth, (req, res) => {
  res.render("iocs/search", {
    title: "Search IoC",
    query: "",
    detectedType: null,
    result: null,
    searched: false
  });
});

router.post("/search", requireAuth, async (req, res, next) => {
  try {
    const query = normalizeIocValue(req.body.value);
    const detectedType = detectIocType(query);
    const result = query ? await Ioc.findOne({ value: query }) : null;

    await writeAuditLog(req.session.user, "IOC_SEARCH", `Searched: ${query || "empty"}`);

    res.render("iocs/search", {
      title: "Search IoC",
      query,
      detectedType,
      result,
      searched: true
    });
  } catch (error) {
    next(error);
  }
});

router.get("/add", requireAdmin, (req, res) => {
  res.render("iocs/add", {
    title: "Add IoC",
    form: {},
    detectedType: null
  });
});

router.post("/add", requireAdmin, async (req, res, next) => {
  try {
    const value = normalizeIocValue(req.body.value);
    if (!value) {
      req.session.errorMessage = "IoC value is required.";
      return res.redirect("/iocs/add");
    }

    const iocType = cleanIocType(req.body.iocType, value);

    await Ioc.create({
      value,
      iocType,
      threatType: String(req.body.threatType || "Unknown Threat").trim(),
      severity: cleanSeverity(req.body.severity),
      confidence: Number(req.body.confidence || 50),
      source: String(req.body.source || "Manual Entry").trim(),
      description: String(req.body.description || "").trim(),
      tags: parseTags(req.body.tags),
      createdBy: req.session.user.id
    });

    await writeAuditLog(req.session.user, "IOC_ADDED", `Added IoC: ${value}`);
    req.session.successMessage = "IoC added successfully.";
    return res.redirect("/iocs");
  } catch (error) {
    if (error.code === 11000) {
      req.session.errorMessage = "This IoC already exists.";
      return res.redirect("/iocs/add");
    }
    next(error);
  }
});

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const search = normalizeIocValue(req.query.search || "");
    const severity = String(req.query.severity || "").trim();
    const iocType = String(req.query.iocType || "").trim();

    const filter = {};
    if (search) {
      filter.$or = [
        { value: { $regex: search, $options: "i" } },
        { threatType: { $regex: search, $options: "i" } },
        { source: { $regex: search, $options: "i" } },
        { tags: { $regex: search, $options: "i" } }
      ];
    }
    if (severity) filter.severity = severity;
    if (iocType) filter.iocType = iocType;

    const iocs = await Ioc.find(filter).sort({ updatedAt: -1 }).limit(200);

    res.render("iocs/list", {
      title: "IoC Repository",
      iocs,
      search,
      severity,
      iocType
    });
  } catch (error) {
    next(error);
  }
});

router.get("/import", requireAdmin, (req, res) => {
  res.render("iocs/import", { title: "Import CSV" });
});

router.post("/import", requireAdmin, upload.single("csvFile"), async (req, res, next) => {
  if (!req.file) {
    req.session.errorMessage = "Please choose a CSV file.";
    return res.redirect("/iocs/import");
  }

  const rows = [];
  const filePath = req.file.path;

  fs.createReadStream(filePath)
    .pipe(csv())
    .on("data", (row) => rows.push(row))
    .on("end", async () => {
      try {
        let imported = 0;
        let skipped = 0;

        for (const row of rows) {
          const value = normalizeIocValue(row.value || row.Value || row.ioc || row.IoC);
          if (!value) {
            skipped += 1;
            continue;
          }

          const doc = {
            value,
            iocType: cleanIocType(row.type || row.iocType || row.Type, value),
            threatType: String(row.threatType || row.threat_type || row.threat || "Unknown Threat").trim(),
            severity: cleanSeverity(row.severity || row.Severity),
            confidence: Number(row.confidence || 50),
            source: String(row.source || "CSV Import").trim(),
            description: String(row.description || "").trim(),
            tags: parseTags(row.tags || ""),
            createdBy: req.session.user.id
          };

          await Ioc.updateOne(
            { value },
            { $set: doc },
            { upsert: true, runValidators: true }
          );
          imported += 1;
        }

        fs.unlink(filePath, () => {});
        await writeAuditLog(req.session.user, "CSV_IMPORT", `Imported/updated ${imported} rows, skipped ${skipped} rows`);
        req.session.successMessage = `CSV processed. Imported/updated: ${imported}, skipped: ${skipped}.`;
        return res.redirect("/iocs");
      } catch (error) {
        fs.unlink(filePath, () => {});
        next(error);
      }
    })
    .on("error", (error) => {
      fs.unlink(filePath, () => {});
      next(error);
    });
});

router.get("/:id/edit", requireAdmin, async (req, res, next) => {
  try {
    const ioc = await Ioc.findById(req.params.id);
    if (!ioc) {
      req.session.errorMessage = "IoC not found.";
      return res.redirect("/iocs");
    }

    return res.render("iocs/edit", {
      title: "Edit IoC",
      ioc
    });
  } catch (error) {
    next(error);
  }
});

router.post("/:id/edit", requireAdmin, async (req, res, next) => {
  try {
    const value = normalizeIocValue(req.body.value);
    const iocType = cleanIocType(req.body.iocType, value);

    await Ioc.findByIdAndUpdate(
      req.params.id,
      {
        value,
        iocType,
        threatType: String(req.body.threatType || "Unknown Threat").trim(),
        severity: cleanSeverity(req.body.severity),
        confidence: Number(req.body.confidence || 50),
        source: String(req.body.source || "Manual Entry").trim(),
        description: String(req.body.description || "").trim(),
        tags: parseTags(req.body.tags)
      },
      { runValidators: true }
    );

    await writeAuditLog(req.session.user, "IOC_UPDATED", `Updated IoC: ${value}`);
    req.session.successMessage = "IoC updated successfully.";
    return res.redirect("/iocs");
  } catch (error) {
    next(error);
  }
});

router.post("/:id/delete", requireAdmin, async (req, res, next) => {
  try {
    const ioc = await Ioc.findByIdAndDelete(req.params.id);
    if (ioc) {
      await writeAuditLog(req.session.user, "IOC_DELETED", `Deleted IoC: ${ioc.value}`);
    }

    req.session.successMessage = "IoC deleted successfully.";
    return res.redirect("/iocs");
  } catch (error) {
    next(error);
  }
});

module.exports = router;