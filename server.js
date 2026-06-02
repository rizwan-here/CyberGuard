require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const connectDB = require("./config/db");
const seedDefaultUsers = require("./utils/seedAdmin");
const { attachUser } = require("./middleware/auth");

const authRoutes = require("./routes/authRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const iocRoutes = require("./routes/iocRoutes");
const reportRoutes = require("./routes/reportRoutes");
const browserScanRoutes = require("./routes/browserScanRoutes");
const apiRoutes = require("./routes/apiRoutes"); // New API routes

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || require("crypto").randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 3
    }
  })
);

app.use(attachUser);

app.use(authRoutes);
app.use("/", dashboardRoutes);
app.use("/iocs", iocRoutes);
app.use("/iocs", browserScanRoutes);
app.use("/reports", reportRoutes);
app.use("/api", apiRoutes); // Mount API routes

app.use((req, res) => {
  res.status(404).render("error", {
    title: "Page Not Found",
    message: "The page you requested was not found."
  });
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).render("error", {
    title: "Server Error",
    message: error.message || "Something went wrong."
  });
});

async function startServer() {
  await connectDB();
  await seedDefaultUsers();

  const port = process.env.PORT || 3000;
  const host = process.env.HOST || "127.0.0.1";

  app.listen(port, host, () => {
    console.log(`CyberGuard running at http://${host}:${port}`);
    console.log("Default demo login: admin/admin123 or analyst/analyst123");
  });
}

startServer();