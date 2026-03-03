// models/Scan.js
const mongoose = require("mongoose");

const FindingSchema = new mongoose.Schema(
  {
    checkName: {
      type: String,
      required: true,
      trim: true,
    },
    passed: {
      type: Boolean,
      required: true,
    },
    detail: {
      type: String,
      required: true,
      trim: true,
    },
    severity: {
      type: String,
      enum: ["None", "Low", "Medium", "High", "Critical"],
      default: "None",
    },
    weight: {
      type: Number,
      default: 0,
      min: 0,
      max: 25,
    },
    // OWASP API Security Top 10 (2023) category mapping
    // Gives each finding real-world context and industry credibility
    owasp: {
      type: String,
      default: "N/A",
      trim: true,
    },
    // Actionable fix recommendation for the developer
    remediation: {
      type: String,
      default: "",
      trim: true,
    },
  },
  { _id: false },
);

const ScanSchema = new mongoose.Schema(
  {
    target: {
      type: String,
      required: [true, "Target URL is required"],
      trim: true,
    },
    endpoint: {
      type: String,
      trim: true,
      default: "/",
    },
    findings: {
      type: [FindingSchema],
      default: [],
    },
    overallScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    severity: {
      type: String,
      enum: ["Secure", "Low Risk", "Medium Risk", "High Risk", "Critical"],
      required: true,
    },
    scanDuration: {
      type: Number,
      default: 0,
    },
    tokenUsed: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);

ScanSchema.index({ target: 1 });
ScanSchema.index({ target: 1, createdAt: -1 });
ScanSchema.index({ severity: 1 });

ScanSchema.virtual("fullUrl").get(function () {
  const ep = this.endpoint && this.endpoint !== "/" ? this.endpoint : "";
  return `${this.target}${ep}`;
});

ScanSchema.set("toJSON", { virtuals: true });

module.exports = mongoose.model("Scan", ScanSchema);
