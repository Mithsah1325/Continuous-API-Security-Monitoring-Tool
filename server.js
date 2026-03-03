// server.js
// Application entry point.

const dotenv = require("dotenv");
dotenv.config(); // Must be first — loads .env before anything reads process.env

const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");
const apiRoutes = require("./routes/api");

// Connect to MongoDB Atlas
connectDB();

const app = express();

// ── Middleware ────────────────────────────────────────────────────
app.use(express.json()); // Parse JSON request bodies
app.use(cors()); // Allow cross-origin requests
app.use(express.static("public")); // Serve frontend from /public

// ── API Routes ────────────────────────────────────────────────────
// All routes defined in routes/api.js are mounted under /api
app.use("/api", apiRoutes);

// ── Health Check ──────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "APIFortify server is running",
    timestamp: new Date().toISOString(),
  });
});

// ── Global Error Handler ──────────────────────────────────────────
// Catches any unhandled errors from routes/controllers
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({
    success: false,
    message: "An unexpected server error occurred.",
  });
});

// ── Start Server ──────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
