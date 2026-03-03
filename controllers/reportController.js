// controllers/reportController.js
// Handles PDF report generation requests.
// Fetches the scan from MongoDB and streams a PDF to the client.

const Scan = require("../models/Scan");
const { generatePDFReport } = require("../services/reportGenerator");

const downloadPDFReport = async (req, res) => {
  try {
    const { id } = req.params;

    // Fetch the full scan document including findings
    const scan = await Scan.findById(id);

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: "Scan not found.",
      });
    }

    // Set response headers for PDF download
    const filename = `apifortify-report-${scan.target.replace(/[^a-z0-9]/gi, "-")}-${Date.now()}.pdf`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

    // Stream PDF directly into response
    generatePDFReport(scan, res);
  } catch (error) {
    if (error.name === "CastError") {
      return res
        .status(400)
        .json({ success: false, message: "Invalid scan ID." });
    }
    console.error("PDF generation error:", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to generate PDF report." });
  }
};

module.exports = { downloadPDFReport };
