const express = require("express");
const fs = require("fs");
const multer = require("multer");
const csv = require("csv-parser");
const Ioc = require("../models/Ioc");
const { requireAuth, requireAdmin } = require("../middleware/auth");
const { detectIocType, normalizeIocValue } = require("../utils/detectIocType");
const writeAuditLog = require("../utils/audit");

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

// Helper to explain WHY an IoC was categorized a certain way (For UI Demonstration)
function analyzeIoc(value) {
  if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value)) {
      return { type: 'IP', rule: 'Matches IPv4 octet pattern (e.g., xxx.xxx.xxx.xxx)' };
  }
  if (/^[A-Fa-f0-9]{32}$/.test(value)) return { type: 'MD5', rule: '32-character Hexadecimal string' };
  if (/^[A-Fa-f0-9]{40}$/.test(value)) return { type: 'SHA1', rule: '40-character Hexadecimal string' };
  if (/^[A-Fa-f0-9]{64}$/.test(value)) return { type: 'SHA256', rule: '64-character Hexadecimal signature' };
  if (/^https?:\/\//.test(value)) return { type: 'URL', rule: 'Starts with HTTP/HTTPS protocol' };
  if (/@/.test(value)) return { type: 'Email', rule: 'Contains @ routing symbol' };
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return { type: 'Domain', rule: 'Standard Domain Name pattern' };
  
  return { type: 'Unknown', rule: 'No matching signature found' };
}

// ---------------------------------------------------------
// EXPORT FEATURE (Step 4: Deployment Demonstration)
// ---------------------------------------------------------
router.get("/export", requireAdmin, async (req, res, next) => {
  try {
    const iocs = await Ioc.find({}).sort({ updatedAt: -1 });
    
    // Create CSV headers
    let csvData = "Value,Type,ThreatType,Severity,Confidence,Source,Tags,CreatedAt\n";
    
    // Append rows
    iocs.forEach(ioc => {
      const tags = ioc.tags.join("; ");
      csvData += `"${ioc.value}","${ioc.iocType}","${ioc.threatType}","${ioc.severity}",${ioc.confidence},"${ioc.source}","${tags}","${ioc.createdAt}"\n`;
    });

    await writeAuditLog(req.session.user, "IOC_EXPORT", `Exported ${iocs.length} IoCs to CSV`);

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=\"cyberguard_iocs.csv\"');
    return res.status(200).send(csvData);
  } catch (error) {
    next(error);
  }
});


// ---------------------------------------------------------
// CSV IMPORT LOGIC (Steps 1, 2, and 3)
// ---------------------------------------------------------
router.get("/import", requireAdmin, (req, res) => {
  res.render("iocs/import", { title: "Import CSV" });
});

// Step 1 & 2: Read CSV, analyze patterns, and render the review page
router.post("/import", requireAdmin, upload.single("csvFile"), (req, res, next) => {
  if (!req.file) {
    req.session.errorMessage = "Please choose a CSV file.";
    return res.redirect("/iocs/import");
  }

  const rows = [];
  const filePath = req.file.path;

  fs.createReadStream(filePath)
    .pipe(csv())
    .on("data", (row) => rows.push(row))
    .on("end", () => {
      const previewData = [];
      
      rows.forEach(row => {
        const value = normalizeIocValue(row.value || row.Value || row.ioc || row.IoC);
        if (!value) return;

        // Extract and enrich the data to show the user
        const analysis = analyzeIoc(value);
        
        previewData.push({
          value,
          detectedType: analysis.type,
          detectionRule: analysis.rule,
          threatType: String(row.threatType || row.threat_type || row.threat || "Unknown Threat").trim(),
          severity: cleanSeverity(row.severity || row.Severity),
          confidence: Number(row.confidence || 50),
          source: String(row.source || "CSV Import").trim(),
          tags: row.tags || ""
        });
      });

      fs.unlink(filePath, () => {}); // Clean up temp file
      
      // Render Step 2 (The Staging Area)
      res.render("iocs/import-review", { 
        title: "Review & Categorize IoCs", 
        iocs: JSON.stringify(previewData),
        displayData: previewData 
      });
    })
    .on("error", (error) => {
      fs.unlink(filePath, () => {});
      next(error);
    });
});

// Step 3: Admin clicks save, write to database
router.post("/import/confirm", requireAdmin, async (req, res, next) => {
  try {
    const iocsData = JSON.parse(req.body.iocsData);
    let imported = 0;

    for (const item of iocsData) {
      const doc = {
        value: item.value,
        iocType: item.detectedType,
        threatType: item.threatType,
        severity: item.severity,
        confidence: item.confidence,
        source: item.source,
        tags: parseTags(item.tags),
        createdBy: req.session.user.id
      };

      await Ioc.updateOne(
        { value: item.value },
        { $set: doc },
        { upsert: true, runValidators: true }
      );
      imported += 1;
    }

    await writeAuditLog(req.session.user, "CSV_IMPORT_CONFIRMED", `Imported/updated ${imported} rows via UI`);
    req.session.successMessage = `Successfully deployed ${imported} IoCs into the repository.`;
    return res.redirect("/iocs");

  } catch (error) {
    next(error);
  }
});
// ---------------------------------------------------------


// Standard Search Route
router.get("/search", requireAuth, (req, res) => {
  res.render("iocs/search", { title: "Search IoC", query: "", detectedType: null, result: null, searched: false });
});

router.post("/search", requireAuth, async (req, res, next) => {
  try {
    const query = normalizeIocValue(req.body.value);
    const detectedType = detectIocType(query);
    const result = query ? await Ioc.findOne({ value: query }) : null;
    await writeAuditLog(req.session.user, "IOC_SEARCH", `Searched: ${query || "empty"}`);
    res.render("iocs/search", { title: "Search IoC", query, detectedType, result, searched: true });
  } catch (error) { next(error); }
});

// Standard Add Route
router.get("/add", requireAdmin, (req, res) => {
  res.render("iocs/add", { title: "Add IoC", form: {}, detectedType: null });
});

router.post("/add", requireAdmin, async (req, res, next) => {
  try {
    const value = normalizeIocValue(req.body.value);
    if (!value) { req.session.errorMessage = "IoC value is required."; return res.redirect("/iocs/add"); }
    const iocType = cleanIocType(req.body.iocType, value);
    await Ioc.create({
      value, iocType, threatType: String(req.body.threatType || "Unknown Threat").trim(),
      severity: cleanSeverity(req.body.severity), confidence: Number(req.body.confidence || 50),
      source: String(req.body.source || "Manual Entry").trim(), description: String(req.body.description || "").trim(),
      tags: parseTags(req.body.tags), createdBy: req.session.user.id
    });
    await writeAuditLog(req.session.user, "IOC_ADDED", `Added IoC: ${value}`);
    req.session.successMessage = "IoC added successfully.";
    return res.redirect("/iocs");
  } catch (error) {
    if (error.code === 11000) { req.session.errorMessage = "This IoC already exists."; return res.redirect("/iocs/add"); }
    next(error);
  }
});

// Standard List Route (With the user fix applied)
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
      iocType,
      user: req.session.user // <--- User fix added here
    });
  } catch (error) {
    next(error);
  }
});

// Standard Edit & Delete Routes
router.get("/:id/edit", requireAdmin, async (req, res, next) => {
  try {
    const ioc = await Ioc.findById(req.params.id);
    if (!ioc) { req.session.errorMessage = "IoC not found."; return res.redirect("/iocs"); }
    return res.render("iocs/edit", { title: "Edit IoC", ioc });
  } catch (error) { next(error); }
});

router.post("/:id/edit", requireAdmin, async (req, res, next) => {
  try {
    const value = normalizeIocValue(req.body.value);
    const iocType = cleanIocType(req.body.iocType, value);
    await Ioc.findByIdAndUpdate(
      req.params.id,
      {
        value, iocType, threatType: String(req.body.threatType || "Unknown Threat").trim(),
        severity: cleanSeverity(req.body.severity), confidence: Number(req.body.confidence || 50),
        source: String(req.body.source || "Manual Entry").trim(), description: String(req.body.description || "").trim(),
        tags: parseTags(req.body.tags)
      },
      { runValidators: true }
    );
    await writeAuditLog(req.session.user, "IOC_UPDATED", `Updated IoC: ${value}`);
    req.session.successMessage = "IoC updated successfully.";
    return res.redirect("/iocs");
  } catch (error) { next(error); }
});

router.post("/:id/delete", requireAdmin, async (req, res, next) => {
  try {
    const ioc = await Ioc.findByIdAndDelete(req.params.id);
    if (ioc) await writeAuditLog(req.session.user, "IOC_DELETED", `Deleted IoC: ${ioc.value}`);
    req.session.successMessage = "IoC deleted successfully.";
    return res.redirect("/iocs");
  } catch (error) { next(error); }
});

module.exports = router;