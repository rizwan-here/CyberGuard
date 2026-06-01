require("dotenv").config();

const mongoose = require("mongoose");
const connectDB = require("../config/db");
const Ioc = require("../models/Ioc");
const seedDefaultUsers = require("../utils/seedAdmin");

const demoIocs = [
  {
    value: "203.0.113.10",
    iocType: "IP",
    threatType: "Malware C2",
    severity: "High",
    confidence: 85,
    source: "Internal SOC Feed",
    description: "Demo command-and-control IP for classroom project",
    tags: ["malware", "c2"]
  },
  {
    value: "malicious-demo.test",
    iocType: "Domain",
    threatType: "Phishing",
    severity: "Medium",
    confidence: 70,
    source: "Manual Feed",
    description: "Demo phishing domain for CyberGuard testing",
    tags: ["phishing", "demo"]
  },
  {
    value: "https://malicious-demo.test/login",
    iocType: "URL",
    threatType: "Credential Harvesting",
    severity: "Critical",
    confidence: 90,
    source: "Threat Hunting",
    description: "Demo credential harvesting URL",
    tags: ["phishing", "credential-theft"]
  },
  {
    value: "44d88612fea8a8f36de82e1278abb02f",
    iocType: "MD5",
    threatType: "Malware Sample",
    severity: "High",
    confidence: 95,
    source: "Malware Lab",
    description: "Demo malware hash for IoC search testing",
    tags: ["malware", "hash"]
  },
  {
    value: "attacker@example.test",
    iocType: "Email",
    threatType: "Phishing Sender",
    severity: "Medium",
    confidence: 65,
    source: "Email Gateway",
    description: "Demo suspicious sender email",
    tags: ["email", "phishing"]
  }
];

async function seed() {
  await connectDB();
  await seedDefaultUsers();

  for (const item of demoIocs) {
    await Ioc.updateOne({ value: item.value }, { $set: item }, { upsert: true, runValidators: true });
  }

  console.log(`Seeded ${demoIocs.length} demo IoCs.`);
  await mongoose.connection.close();
}

seed().catch(async (error) => {
  console.error(error);
  await mongoose.connection.close();
  process.exit(1);
});
