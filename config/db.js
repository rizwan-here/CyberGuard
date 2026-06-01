const mongoose = require("mongoose");

async function connectDB() {
  const mongoUri = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/cyberguard";

  try {
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000
    });
    console.log("MongoDB connected:", mongoUri);
  } catch (error) {
    console.error("MongoDB connection failed.");
    console.error("Make sure MongoDB Community Server is installed and running locally.");
    console.error("Connection string:", mongoUri);
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = connectDB;
