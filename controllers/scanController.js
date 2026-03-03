// controllers/scanController.js
// Handles all scan-related HTTP requests.
//
// Functions exported:
//   createScan  — POST /api/scan     — run a new scan and save results
//   getAllScans — GET  /api/scans    — get scan history (all or by target)
//   getScanById — GET  /api/scans/:id — get one specific scan result
//   deleteScan  — DELETE /api/scans/:id — delete a scan record

const Scan = require("../models/Scan");
const { runAllChecks } = require("../services/scanner");
const { calculateRisk } = require("../services/riskEngine");

const normalizeEndpoint = (value) => {
  const raw = (value || "").trim();
  if (!raw) return "/";
  return raw.startsWith("/") ? raw : `/${raw}`;
};

const normalizeToken = (value) => {
  const raw = (value || "").trim();
  if (!raw) return null;
  return raw.replace(/^Bearer\s+/i, "");
};

// ─────────────────────────────────────────────────────────────────
// CREATE SCAN
// POST /api/scan
// Body: { target, endpoint, token }
//
// Flow:
//   1. Validate input
//   2. Run all 7 security checks via scanner.js
//   3. Calculate risk score via riskEngine.js
//   4. Save result to MongoDB
//   5. Return result to client
// ─────────────────────────────────────────────────────────────────
const createScan = async (req, res) => {
  try {
    const { target, endpoint, token } = req.body;
    const normalizedTarget = target ? target.trim() : "";
    const normalizedEndpoint = normalizeEndpoint(endpoint);
    const normalizedToken = normalizeToken(token);

    // ── Input Validation ────────────────────────────────────────
    if (!normalizedTarget) {
      return res.status(400).json({
        success: false,
        message: "Target URL is required.",
      });
    }

    // Basic URL format check
    // Must start with http:// or https://
    const urlPattern = /^https?:\/\/.+/i;
    if (!urlPattern.test(normalizedTarget)) {
      return res.status(400).json({
        success: false,
        message: "Target must be a valid URL starting with http:// or https://",
      });
    }

    // ── Run Scanner ─────────────────────────────────────────────
    // Record start time to calculate scan duration
    const scanStart = Date.now();

    console.log(`🔍 Starting scan for: ${normalizedTarget}${normalizedEndpoint === "/" ? "" : normalizedEndpoint}`);

    // Run all 9 checks in parallel — returns findings[]
    const findings = await runAllChecks(
      normalizedTarget,
      normalizedEndpoint,
      normalizedToken,
    );

    const scanDuration = Date.now() - scanStart;

    console.log(
      `✅ Scan complete in ${scanDuration}ms — ${findings.length} checks performed`,
    );

    // ── Calculate Risk ──────────────────────────────────────────
    // Pass findings to risk engine to get score and severity label
    const { overallScore, severity } = calculateRisk(findings);

    // ── Save to MongoDB ─────────────────────────────────────────
    const scan = await Scan.create({
      target: normalizedTarget,
      endpoint: normalizedEndpoint,
      findings,
      overallScore,
      severity,
      scanDuration,
      tokenUsed: !!normalizedToken, // true if token was provided, false otherwise
    });

    console.log(`💾 Scan saved to MongoDB with ID: ${scan._id}`);

    // ── Send Response ───────────────────────────────────────────
    return res.status(201).json({
      success: true,
      message: "Scan completed successfully.",
      data: scan,
    });
  } catch (error) {
    console.error("❌ Scan error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Scan failed due to a server error.",
      error: error.message,
    });
  }
};

// ─────────────────────────────────────────────────────────────────
// GET ALL SCANS
// GET /api/scans
// Optional query param: ?target=https://api.example.com
//
// Returns scan history, newest first.
// If target param is provided, filters to that target only.
// ─────────────────────────────────────────────────────────────────
const getAllScans = async (req, res) => {
  try {
    const { target, limit = 20, page = 1 } = req.query;

    // Build filter object
    // If target is provided, filter by it — uses the index we created
    const filter = {};
    if (target) {
      filter.target = target.trim();
    }

    // Pagination values
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    // Fetch scans — sorted newest first
    // We exclude the full findings array from the list view
    // (saves bandwidth — findings are fetched in the detail view)
    const scans = await Scan.find(filter)
      .sort({ createdAt: -1 }) // newest first — uses our index
      .skip(skip)
      .limit(limitNum)
      .select("-findings"); // exclude findings array from list

    // Total count for pagination
    const total = await Scan.countDocuments(filter);

    return res.status(200).json({
      success: true,
      total,
      page: pageNum,
      pages: Math.ceil(total / limitNum),
      data: scans,
    });
  } catch (error) {
    console.error("❌ Get scans error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to retrieve scans.",
      error: error.message,
    });
  }
};

// ─────────────────────────────────────────────────────────────────
// GET SCAN BY ID
// GET /api/scans/:id
//
// Returns one complete scan document including full findings array.
// This is the detail view — called when user clicks a scan result.
// ─────────────────────────────────────────────────────────────────
const getScanById = async (req, res) => {
  try {
    const { id } = req.params;

    // findById uses MongoDB's _id field
    const scan = await Scan.findById(id);

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found.",
      });
    }

    return res.status(200).json({
      success: true,
      data: scan,
    });
  } catch (error) {
    // Mongoose throws CastError if id format is invalid
    if (error.name === "CastError") {
      return res.status(400).json({
        success: false,
        message: "Invalid scan ID format.",
      });
    }

    console.error("❌ Get scan by ID error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to retrieve scan.",
      error: error.message,
    });
  }
};

// ─────────────────────────────────────────────────────────────────
// DELETE SCAN
// DELETE /api/scans/:id
//
// Removes one scan document from MongoDB.
// ─────────────────────────────────────────────────────────────────
const deleteScan = async (req, res) => {
  try {
    const { id } = req.params;

    const scan = await Scan.findByIdAndDelete(id);

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Scan deleted successfully.",
    });
  } catch (error) {
    if (error.name === "CastError") {
      return res.status(400).json({
        success: false,
        message: "Invalid scan ID format.",
      });
    }

    console.error("❌ Delete scan error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to delete scan.",
      error: error.message,
    });
  }
};

module.exports = {
  createScan,
  getAllScans,
  getScanById,
  deleteScan,
};
