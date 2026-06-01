const express = require("express");
const Ioc = require("../models/Ioc");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const [bySeverity, byType, byThreatType, topSources, recentCritical] = await Promise.all([
      Ioc.aggregate([{ $group: { _id: "$severity", count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Ioc.aggregate([{ $group: { _id: "$iocType", count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Ioc.aggregate([{ $group: { _id: "$threatType", count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Ioc.aggregate([{ $group: { _id: "$source", count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Ioc.find({ severity: { $in: ["Critical", "High"] } }).sort({ updatedAt: -1 }).limit(15)
    ]);

    res.render("reports", {
      title: "Threat Reports",
      bySeverity,
      byType,
      byThreatType,
      topSources,
      recentCritical
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
