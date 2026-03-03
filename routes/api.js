// routes/api.js
// Defines all API routes and maps them to controller functions.
//
// Route map:
//   POST   /api/scan              → createScan
//   GET    /api/scans             → getAllScans
//   GET    /api/scans/:id         → getScanById
//   DELETE /api/scans/:id         → deleteScan
//   GET    /api/stats/severity    → getSeverityDistribution
//   GET    /api/stats/findings    → getMostCommonFindings
//   GET    /api/stats/history     → getTargetHistory
//   GET    /api/stats/summary     → getDashboardSummary

const express = require("express");
const router = express.Router();

// Import controllers
const {
  createScan,
  getAllScans,
  getScanById,
  deleteScan,
} = require("../controllers/scanController");

const { downloadPDFReport } = require("../controllers/reportController");

const {
  getSeverityDistribution,
  getMostCommonFindings,
  getTargetHistory,
  getDashboardSummary,
} = require("../controllers/statsController");

router.get("/report/:id/pdf", downloadPDFReport);

// ── Scan Routes ───────────────────────────────────────────────────
router.post("/scan", createScan); // Run a new scan
router.get("/scans", getAllScans); // Get all scans / filter by target
router.get("/scans/:id", getScanById); // Get one scan by ID
router.delete("/scans/:id", deleteScan); // Delete a scan

// ── Stats Routes ──────────────────────────────────────────────────
router.get("/stats/summary", getDashboardSummary); // Dashboard numbers
router.get("/stats/severity", getSeverityDistribution); // Severity breakdown
router.get("/stats/findings", getMostCommonFindings); // Most failed checks
router.get("/stats/history", getTargetHistory); // Per-target history

module.exports = router;
