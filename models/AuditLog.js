const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      default: "system"
    },
    action: {
      type: String,
      required: true
    },
    details: {
      type: String,
      default: ""
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("AuditLog", auditLogSchema);
