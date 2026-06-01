const AuditLog = require("../models/AuditLog");

async function writeAuditLog(user, action, details = "") {
  try {
    await AuditLog.create({
      username: user?.username || "system",
      action,
      details
    });
  } catch (error) {
    console.error("Audit log failed:", error.message);
  }
}

module.exports = writeAuditLog;
