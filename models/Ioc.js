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

// POST-SAVE HOOK: Push to SIEM Webhook
iocSchema.post('save', async function(doc) {
  const webhookUrl = process.env.SIEM_WEBHOOK_URL;
  if (!webhookUrl) return; // Skip if no SIEM configured

  try {
      const payload = {
          action: "NEW_IOC_ADDED",
          ioc_value: doc.value,
          ioc_type: doc.iocType,
          threat_type: doc.threatType,
          severity: doc.severity,
          source: "CyberGuard_TIP"
      };

      // Native Node.js fetch (Requires Node v18+)
      await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
      });
      console.log(`[+] Successfully pushed IoC ${doc.value} to SIEM webhook.`);
  } catch (error) {
      console.error(`[-] Failed to push to SIEM webhook:`, error.message);
  }
});

module.exports = mongoose.model("Ioc", iocSchema);