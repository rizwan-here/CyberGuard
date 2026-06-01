const express = require("express");
const Ioc = require("../models/Ioc");
const AuditLog = require("../models/AuditLog");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const [totalIocs, criticalIocs, highIocs, recentIocs, byType, bySeverity, recentLogs] = await Promise.all([
      Ioc.countDocuments(),
      Ioc.countDocuments({ severity: "Critical" }),
      Ioc.countDocuments({ severity: "High" }),
      Ioc.find().sort({ createdAt: -1 }).limit(8),
      Ioc.aggregate([{ $group: { _id: "$iocType", count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Ioc.aggregate([{ $group: { _id: "$severity", count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      AuditLog.find().sort({ createdAt: -1 }).limit(6)
    ]);

    res.render("dashboard", {
      title: "Dashboard",
      totalIocs,
      criticalIocs,
      highIocs,
      recentIocs,
      byType,
      bySeverity,
      recentLogs
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
