const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    displayName: {
      type: String,
      trim: true,
      default: "SOC User"
    },
    passwordHash: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ["admin", "analyst"],
      default: "analyst"
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
