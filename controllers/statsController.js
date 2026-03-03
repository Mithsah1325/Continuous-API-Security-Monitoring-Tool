// controllers/statsController.js
// Handles all aggregation-based statistics queries.
//
// This is where MongoDB's aggregation pipeline shines.
// We answer analytical questions about scan data without
// pulling raw documents into Node.js and processing them manually.
// MongoDB does the heavy lifting inside the database engine.
//
// Functions exported:
//   getSeverityDistribution — how many scans per severity level
//   getMostCommonFindings   — which checks fail most often
//   getTargetHistory        — scan history and trend for one target
//   getDashboardSummary     — all stats combined for dashboard

const Scan = require("../models/Scan");

// ─────────────────────────────────────────────────────────────────
// SEVERITY DISTRIBUTION
// GET /api/stats/severity
//
// Aggregation Pipeline:
//   Stage 1: $group — group all documents by severity field
//                     count how many documents in each group
//   Stage 2: $sort  — sort by count descending (most common first)
//
// Example output:
//   [ { severity: "Medium Risk", count: 45 },
//     { severity: "High Risk",   count: 23 }, ... ]
// ─────────────────────────────────────────────────────────────────
const getSeverityDistribution = async (req, res) => {
  try {
    const distribution = await Scan.aggregate([
      {
        // Stage 1: Group by severity and count documents in each group
        // _id is the field we group by
        // count uses $sum: 1 to add 1 for each document in the group
        $group: {
          _id: "$severity",
          count: { $sum: 1 },
          // Also calculate average score per severity group
          avgScore: { $avg: "$overallScore" },
        },
      },
      {
        // Stage 2: Sort by count descending
        $sort: { count: -1 },
      },
      {
        // Stage 3: Rename _id to severity for cleaner output
        $project: {
          _id: 0,
          severity: "$_id",
          count: 1,
          avgScore: { $round: ["$avgScore", 1] },
        },
      },
    ]);

    return res.status(200).json({
      success: true,
      data: distribution,
    });
  } catch (error) {
    console.error("❌ Severity distribution error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to get severity distribution.",
      error: error.message,
    });
  }
};

// ─────────────────────────────────────────────────────────────────
// MOST COMMON FINDINGS
// GET /api/stats/findings
//
// Aggregation Pipeline:
//   Stage 1: $unwind  — flatten findings array
//                       one document becomes multiple (one per finding)
//   Stage 2: $match   — only keep failed findings (passed: false)
//   Stage 3: $group   — group by checkName, count occurrences
//   Stage 4: $sort    — most frequent first
//   Stage 5: $limit   — top 10 only
//
// This is the most powerful aggregation — it requires $unwind to
// "explode" the embedded array before we can group by finding type.
//
// Example output:
//   [ { checkName: "Rate Limiting", failCount: 67 },
//     { checkName: "Security Headers", failCount: 54 }, ... ]
// ─────────────────────────────────────────────────────────────────
const getMostCommonFindings = async (req, res) => {
  try {
    const commonFindings = await Scan.aggregate([
      {
        // Stage 1: Unwind the findings array
        // Each scan document with 7 findings becomes 7 separate documents
        // Each document has one finding from the original array
        $unwind: "$findings",
      },
      {
        // Stage 2: Filter to only failed checks
        // We only care about what went wrong, not what passed
        $match: { "findings.passed": false },
      },
      {
        // Stage 3: Group by the check name
        // Count how many times each check failed across all scans
        $group: {
          _id: "$findings.checkName",
          failCount: { $sum: 1 },
          // Collect unique severity values for this check
          severities: { $addToSet: "$findings.severity" },
        },
      },
      {
        // Stage 4: Sort by fail count descending
        $sort: { failCount: -1 },
      },
      {
        // Stage 5: Only return top 10 most common failures
        $limit: 10,
      },
      {
        // Stage 6: Clean up the output
        $project: {
          _id: 0,
          checkName: "$_id",
          failCount: 1,
          severities: 1,
        },
      },
    ]);

    return res.status(200).json({
      success: true,
      data: commonFindings,
    });
  } catch (error) {
    console.error("❌ Common findings error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to get common findings.",
      error: error.message,
    });
  }
};

// ─────────────────────────────────────────────────────────────────
// TARGET HISTORY
// GET /api/stats/history?target=https://api.example.com
//
// Returns all scans for a specific target with score trend.
// Shows how the security posture of one API changes over time.
//
// Aggregation Pipeline:
//   Stage 1: $match  — filter to specific target
//   Stage 2: $sort   — oldest first (for trend chart)
//   Stage 3: $project — return only fields needed for history view
// ─────────────────────────────────────────────────────────────────
const getTargetHistory = async (req, res) => {
  try {
    const { target } = req.query;

    if (!target) {
      return res.status(400).json({
        success: false,
        message: "Target query parameter is required.",
      });
    }

    const history = await Scan.aggregate([
      {
        // Stage 1: Filter to this specific target
        // Uses our { target: 1 } index for fast lookup
        $match: { target: target.trim() },
      },
      {
        // Stage 2: Sort oldest first — good for trend line charts
        $sort: { createdAt: 1 },
      },
      {
        // Stage 3: Select only the fields we need
        // Excludes the full findings array — we don't need it for history
        $project: {
          _id: 1,
          target: 1,
          endpoint: 1,
          overallScore: 1,
          severity: 1,
          scanDuration: 1,
          createdAt: 1,
          // Count how many checks failed in this scan
          failedChecks: {
            $size: {
              $filter: {
                input: "$findings",
                as: "f",
                cond: { $eq: ["$$f.passed", false] },
              },
            },
          },
        },
      },
    ]);

    return res.status(200).json({
      success: true,
      target,
      totalScans: history.length,
      data: history,
    });
  } catch (error) {
    console.error("❌ Target history error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to get target history.",
      error: error.message,
    });
  }
};

// ─────────────────────────────────────────────────────────────────
// DASHBOARD SUMMARY
// GET /api/stats/summary
//
// Returns all key numbers for the dashboard in one request:
//   - Total scans performed
//   - Average security score across all scans
//   - Count of scans by severity
//   - Most recently scanned targets
// ─────────────────────────────────────────────────────────────────
const getDashboardSummary = async (req, res) => {
  try {
    // Run all summary queries in parallel using Promise.all
    // Much faster than running them sequentially
    const [totals, recentScans, uniqueTargets] = await Promise.all([
      // Query 1: Overall totals and averages
      Scan.aggregate([
        {
          $group: {
            _id: null, // null means group ALL documents together
            totalScans: { $sum: 1 },
            avgScore: { $avg: "$overallScore" },
            minScore: { $min: "$overallScore" },
            maxScore: { $max: "$overallScore" },
          },
        },
        {
          $project: {
            _id: 0,
            totalScans: 1,
            avgScore: { $round: ["$avgScore", 1] },
            minScore: 1,
            maxScore: 1,
          },
        },
      ]),

      // Query 2: 5 most recent scans for the dashboard feed
      Scan.find()
        .sort({ createdAt: -1 })
        .limit(5)
        .select("target endpoint overallScore severity createdAt"),

      // Query 3: Count distinct targets ever scanned
      Scan.distinct("target"),
    ]);

    return res.status(200).json({
      success: true,
      data: {
        // totals[0] because aggregate returns an array
        summary: totals[0] || {
          totalScans: 0,
          avgScore: 0,
          minScore: 0,
          maxScore: 0,
        },
        uniqueTargetsCount: uniqueTargets.length,
        recentScans,
      },
    });
  } catch (error) {
    console.error("❌ Dashboard summary error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to get dashboard summary.",
      error: error.message,
    });
  }
};

module.exports = {
  getSeverityDistribution,
  getMostCommonFindings,
  getTargetHistory,
  getDashboardSummary,
};
