const express = require("express");
const router = express.Router();
const Ioc = require("../models/Ioc");
const { requireAuth } = require("../middleware/auth");

// Dashboard Route
router.get("/", requireAuth, async (req, res, next) => {
  try {
    // 1. Top-Level Stats
    const totalIocs = await Ioc.countDocuments();
    const criticalIocs = await Ioc.countDocuments({ severity: "Critical" });
    const highIocs = await Ioc.countDocuments({ severity: "High" });
    const uniqueThreats = (await Ioc.distinct("threatType")).length;

    // 2. Chart Data: Severity Distribution
    const severityStats = await Ioc.aggregate([
      { $group: { _id: "$severity", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // 3. Chart Data: IoC Type Distribution
    const typeStats = await Ioc.aggregate([
      { $group: { _id: "$iocType", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // 4. Chart Data: Top 5 Threat Campaigns
    const threatStats = await Ioc.aggregate([
      { $group: { _id: "$threatType", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 6 }
    ]);

    // 5. Recent Activity Table
    const recentIocs = await Ioc.find().sort({ createdAt: -1 }).limit(6);

    res.render("dashboard", {
      title: "SOC Dashboard",
      user: req.session.user,
      stats: { totalIocs, criticalIocs, highIocs, uniqueThreats },
      chartData: {
        severity: JSON.stringify(severityStats),
        types: JSON.stringify(typeStats),
        threats: JSON.stringify(threatStats)
      },
      recentIocs
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;