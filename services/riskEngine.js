// services/riskEngine.js
// Calculates the overall security posture score from scanner findings.
//
// Formula:
//   Start with 100 points (perfect score)
//   Deduct each finding's weight from the score
//   Score cannot go below 0
//
// Severity labels based on final score:
//   90-100  → Secure
//   70-89   → Low Risk
//   50-69   → Medium Risk
//   25-49   → High Risk
//   0-24    → Critical

const calculateRisk = (findings) => {
  // Start with a perfect score
  let score = 100;

  // Add up all penalty weights from failed checks only
  findings.forEach((finding) => {
    if (!finding.passed) {
      score -= finding.weight;
    }
  });

  // Score can never go negative
  score = Math.max(0, score);

  // Round to nearest integer for clean display
  score = Math.round(score);

  // Determine severity label from score
  let severity;
  if (score >= 90) severity = "Secure";
  else if (score >= 70) severity = "Low Risk";
  else if (score >= 50) severity = "Medium Risk";
  else if (score >= 25) severity = "High Risk";
  else severity = "Critical";

  return { overallScore: score, severity };
};

module.exports = { calculateRisk };
