const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const writeAuditLog = require("../utils/audit");

const router = express.Router();

router.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/");
  res.render("auth/login", { title: "Login" });
});

router.post("/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = await User.findOne({ username });
    if (!user) {
      req.session.errorMessage = "Invalid username or password.";
      return res.redirect("/login");
    }

    const passwordOk = await bcrypt.compare(password, user.passwordHash);
    if (!passwordOk) {
      req.session.errorMessage = "Invalid username or password.";
      return res.redirect("/login");
    }

    req.session.user = {
      id: user._id.toString(),
      username: user.username,
      displayName: user.displayName,
      role: user.role
    };

    await writeAuditLog(user, "LOGIN", "User logged in");
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    req.session.errorMessage = "Login failed.";
    return res.redirect("/login");
  }
});

router.post("/logout", async (req, res) => {
  const username = req.session.user?.username;
  if (username) {
    await writeAuditLog(req.session.user, "LOGOUT", "User logged out");
  }

  req.session.destroy(() => {
    res.redirect("/login");
  });
});

module.exports = router;
