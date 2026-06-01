const bcrypt = require("bcryptjs");
const User = require("../models/User");
const writeAuditLog = require("./audit");

async function seedDefaultUsers() {
  const userCount = await User.countDocuments();
  if (userCount > 0) return;

  const adminPasswordHash = await bcrypt.hash("admin123", 10);
  const analystPasswordHash = await bcrypt.hash("analyst123", 10);

  await User.insertMany([
    {
      username: "admin",
      displayName: "CyberGuard Admin",
      passwordHash: adminPasswordHash,
      role: "admin"
    },
    {
      username: "analyst",
      displayName: "SOC Analyst",
      passwordHash: analystPasswordHash,
      role: "analyst"
    }
  ]);

  await writeAuditLog(null, "DEFAULT_USERS_CREATED", "Created admin/admin123 and analyst/analyst123 demo accounts");
  console.log("Default users created: admin/admin123 and analyst/analyst123");
}

module.exports = seedDefaultUsers;
