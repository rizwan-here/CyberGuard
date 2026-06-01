const mongoose = require("mongoose");

const iocSchema = new mongoose.Schema(
  {
    value: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    iocType: {
      type: String,
      required: true,
      enum: ["IP", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email", "Unknown"],
      default: "Unknown"
    },
    threatType: {
      type: String,
      required: true,
      trim: true
    },
    severity: {
      type: String,
      enum: ["Low", "Medium", "High", "Critical"],
      default: "Medium"
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 50
    },
    source: {
      type: String,
      trim: true,
      default: "Manual Entry"
    },
    description: {
      type: String,
      trim: true,
      default: ""
    },
    tags: {
      type: [String],
      default: []
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    }
  },
  { timestamps: true }
);

iocSchema.index({ value: 1 });
iocSchema.index({ severity: 1 });
iocSchema.index({ iocType: 1 });
iocSchema.index({ threatType: 1 });

module.exports = mongoose.model("Ioc", iocSchema);
