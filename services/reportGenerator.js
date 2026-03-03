// services/reportGenerator.js
// APIFortify — Professional PDF Report Generator
// Clean white theme, no emoji, print-friendly
// Footer drawn only on current page — no ghost pages

const PDFDocument = require("pdfkit");

const C = {
  black: "#0f1117",
  darkgray: "#374151",
  gray: "#6b7280",
  lightgray: "#f3f4f6",
  border: "#e5e7eb",
  white: "#ffffff",
  primary: "#2563eb",
  primarylt: "#dbeafe",
  green: "#16a34a",
  greenlt: "#dcfce7",
  yellow: "#ca8a04",
  yellowlt: "#fef9c3",
  orange: "#ea580c",
  orangelt: "#ffedd5",
  red: "#dc2626",
  redlt: "#fee2e2",
  purple: "#9333ea",
  purplelt: "#f3e8ff",
};

const SEV = {
  Critical: { fg: C.purple, bg: C.purplelt },
  High: { fg: C.red, bg: C.redlt },
  Medium: { fg: C.orange, bg: C.orangelt },
  Low: { fg: C.yellow, bg: C.yellowlt },
  None: { fg: C.gray, bg: C.lightgray },
};

const scoreColor = (s) => {
  if (s >= 90) return C.green;
  if (s >= 70) return C.green;
  if (s >= 50) return C.yellow;
  if (s >= 25) return C.orange;
  return C.red;
};

const scoreBg = (s) => {
  if (s >= 90) return C.greenlt;
  if (s >= 70) return C.greenlt;
  if (s >= 50) return C.yellowlt;
  if (s >= 25) return C.orangelt;
  return C.redlt;
};

const generatePDFReport = (scan, res) => {
  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 50, bottom: 70, left: 50, right: 50 },
    autoFirstPage: true,
    bufferPages: true,
    info: {
      Title: "APIFortify Security Report",
      Author: "APIFortify v2.0",
      Subject: "API Security Posture Assessment",
    },
  });

  doc.pipe(res);

  const PW = doc.page.width;
  const PH = doc.page.height;
  const W = PW - 100;
  const L = 50;
  const safe = (s) => (s || "").toString().replace(/[^\x20-\x7E\n\r]/g, "");
  const footerText = `APIFortify v2.0  |  ${new Date().toUTCString()}  |  OWASP API Top 10 (2023)`;
  const CONTENT_BOTTOM = PH - 70;

  // ── Draw Helpers ───────────────────────────────────────────────
  const fill = (x, y, w, h, color) => {
    doc.save().rect(x, y, w, h).fill(color).restore();
  };

  const strokeBox = (x, y, w, h, color, lw = 1) => {
    doc
      .save()
      .rect(x, y, w, h)
      .strokeColor(color)
      .lineWidth(lw)
      .stroke()
      .restore();
  };

  const hr = (y, color = C.border, lw = 1) => {
    doc
      .save()
      .moveTo(L, y)
      .lineTo(L + W, y)
      .strokeColor(color)
      .lineWidth(lw)
      .stroke()
      .restore();
  };

  const badge = (text, x, y, w, fg, bg) => {
    fill(x, y, w, 18, bg);
    strokeBox(x, y, w, 18, fg);
    doc
      .save()
      .fontSize(7.5)
      .fillColor(fg)
      .font("Helvetica-Bold")
      .text(text, x, y + 5, { width: w, align: "center" })
      .restore();
  };

  // Draw footer on the CURRENT page — called before doc.addPage()
  // This ensures footer is on the correct page, never creates a new page
  const drawFooter = () => {
    const fY = PH - 50;
    doc.save();
    doc.rect(0, fY, PW, 50).fill(C.lightgray);
    doc
      .moveTo(L, fY)
      .lineTo(L + W, fY)
      .strokeColor(C.border)
      .lineWidth(1)
      .stroke();
    doc
      .fontSize(7.5)
      .fillColor(C.gray)
      .font("Helvetica")
      .text(footerText, L, fY + 18, { width: W, align: "center" });
    doc.restore();
  };

  const sectionTitle = (text, y) => {
    fill(L, y, W, 28, C.primary);
    doc
      .save()
      .fontSize(11)
      .fillColor(C.white)
      .font("Helvetica-Bold")
      .text(text.toUpperCase(), L + 12, y + 8, { width: W - 20 })
      .restore();
    return y + 38;
  };

  const scales = [
    ["90-100", "Secure", C.green, C.greenlt],
    ["70-89", "Low Risk", C.green, C.greenlt],
    ["50-69", "Medium Risk", C.yellow, C.yellowlt],
    ["25-49", "High Risk", C.orange, C.orangelt],
    ["0-24", "Critical", C.red, C.redlt],
  ];

  // ================================================================
  // PAGE 1 — COVER
  // ================================================================

  fill(0, 0, PW, 8, C.primary);

  fill(L, 25, W, 70, C.primary);
  doc
    .save()
    .fontSize(26)
    .fillColor(C.white)
    .font("Helvetica-Bold")
    .text("APIFortify", L + 15, 35)
    .restore();
  doc
    .save()
    .fontSize(10)
    .fillColor("#bfdbfe")
    .font("Helvetica")
    .text("API Security Posture Assessment Platform", L + 15, 65)
    .restore();
  doc
    .save()
    .fontSize(9)
    .fillColor("#bfdbfe")
    .font("Helvetica")
    .text("SECURITY ASSESSMENT REPORT", L + 15, 82, {
      width: W - 20,
      align: "right",
    })
    .restore();

  const scoreVal = scan.overallScore;
  const sCol = scoreColor(scoreVal);
  const sBg = scoreBg(scoreVal);

  fill(L, 110, 130, 100, sBg);
  strokeBox(L, 110, 130, 100, sCol, 2);
  doc
    .save()
    .fontSize(48)
    .fillColor(sCol)
    .font("Helvetica-Bold")
    .text(scoreVal.toString(), L, 122, { width: 130, align: "center" })
    .restore();
  doc
    .save()
    .fontSize(10)
    .fillColor(sCol)
    .font("Helvetica")
    .text("out of 100", L, 165, { width: 130, align: "center" })
    .restore();

  fill(L + 140, 110, 150, 100, sBg);
  strokeBox(L + 140, 110, 150, 100, sCol, 2);
  doc
    .save()
    .fontSize(18)
    .fillColor(sCol)
    .font("Helvetica-Bold")
    .text(safe(scan.severity), L + 140, 148, { width: 150, align: "center" })
    .restore();

  const passed = scan.findings.filter((f) => f.passed).length;
  const failed = scan.findings.length - passed;

  fill(L + 300, 110, 85, 46, C.greenlt);
  strokeBox(L + 300, 110, 85, 46, C.green);
  doc
    .save()
    .fontSize(22)
    .fillColor(C.green)
    .font("Helvetica-Bold")
    .text(passed.toString(), L + 300, 118, { width: 85, align: "center" })
    .restore();
  doc
    .save()
    .fontSize(7.5)
    .fillColor(C.green)
    .font("Helvetica")
    .text("CHECKS PASSED", L + 300, 143, { width: 85, align: "center" })
    .restore();

  fill(L + 300, 164, 85, 46, C.redlt);
  strokeBox(L + 300, 164, 85, 46, C.red);
  doc
    .save()
    .fontSize(22)
    .fillColor(C.red)
    .font("Helvetica-Bold")
    .text(failed.toString(), L + 300, 172, { width: 85, align: "center" })
    .restore();
  doc
    .save()
    .fontSize(7.5)
    .fillColor(C.red)
    .font("Helvetica")
    .text("CHECKS FAILED", L + 300, 197, { width: 85, align: "center" })
    .restore();

  let metaY = 230;
  hr(metaY, C.border);
  metaY += 10;

  const meta = [
    ["Target URL", safe(scan.target)],
    [
      "Endpoint",
      safe(scan.endpoint !== "/" ? scan.endpoint : "(root endpoint)"),
    ],
    ["Full URL", safe(scan.fullUrl || scan.target)],
    ["Scan Date", new Date(scan.createdAt).toLocaleString()],
    ["Duration", `${(scan.scanDuration / 1000).toFixed(2)} seconds`],
    ["Total Checks", `${scan.findings.length} security checks performed`],
    ["Tool Version", "APIFortify v2.0"],
    ["OWASP Coverage", "OWASP API Security Top 10 (2023)"],
  ];

  meta.forEach(([label, value], i) => {
    fill(L, metaY, W, 22, i % 2 === 0 ? C.white : C.lightgray);
    doc
      .save()
      .fontSize(9)
      .fillColor(C.gray)
      .font("Helvetica-Bold")
      .text(label, L + 8, metaY + 6, { width: 120 })
      .restore();
    doc
      .save()
      .fontSize(9)
      .fillColor(C.darkgray)
      .font("Helvetica")
      .text(safe(value), L + 135, metaY + 6, { width: W - 145 })
      .restore();
    metaY += 22;
  });

  hr(metaY + 5, C.border);
  metaY += 20;

  doc
    .save()
    .fontSize(9)
    .fillColor(C.gray)
    .font("Helvetica-Bold")
    .text("RISK SCALE:", L, metaY)
    .restore();
  metaY += 14;

  scales.forEach(([range, label, fg, bg], i) => {
    const sx = L + i * 82;
    fill(sx, metaY, 78, 28, bg);
    strokeBox(sx, metaY, 78, 28, fg);
    doc
      .save()
      .fontSize(7)
      .fillColor(fg)
      .font("Helvetica-Bold")
      .text(range, sx, metaY + 4, { width: 78, align: "center" })
      .restore();
    doc
      .save()
      .fontSize(7)
      .fillColor(fg)
      .font("Helvetica")
      .text(label, sx, metaY + 14, { width: 78, align: "center" })
      .restore();
  });

  // Footer on cover → then new page
  drawFooter();
  doc.addPage();

  // ================================================================
  // PAGE 2 — FINDINGS TABLE
  // ================================================================
  fill(0, 0, PW, 8, C.primary);

  let y = sectionTitle(
    "Security Check Findings — OWASP API Top 10 (2023) Mapped",
    20,
  );

  const cols = {
    num: { x: L, w: 22 },
    check: { x: L + 22, w: 110 },
    status: { x: L + 132, w: 48 },
    severity: { x: L + 180, w: 55 },
    owasp: { x: L + 235, w: 130 },
    penalty: { x: L + 365, w: 45 },
  };

  const drawTableHeader = (startY) => {
    fill(L, startY, W, 24, C.darkgray);
    doc.save().fontSize(7.5).fillColor(C.white).font("Helvetica-Bold");
    [
      [cols.num, "#"],
      [cols.check, "CHECK NAME"],
      [cols.status, "STATUS"],
      [cols.severity, "SEVERITY"],
      [cols.owasp, "OWASP CATEGORY"],
      [cols.penalty, "PENALTY"],
    ].forEach(([col, label]) => {
      doc.text(label, col.x + 4, startY + 8, { width: col.w - 4 });
    });
    doc.restore();
    return startY + 24;
  };

  y = drawTableHeader(y);

  scan.findings.forEach((f, i) => {
    const rowH = 30;

    if (y + rowH > CONTENT_BOTTOM) {
      drawFooter();
      doc.addPage();
      fill(0, 0, PW, 8, C.primary);
      y = drawTableHeader(20);
    }

    const rowBg = i % 2 === 0 ? C.white : C.lightgray;
    const accentFg = f.passed ? C.green : SEV[f.severity]?.fg || C.gray;

    fill(L, y, W, rowH, rowBg);
    fill(L, y, 3, rowH, accentFg);

    doc
      .save()
      .fontSize(8)
      .fillColor(C.gray)
      .font("Helvetica")
      .text((i + 1).toString(), cols.num.x + 4, y + 11, { width: cols.num.w })
      .restore();
    doc
      .save()
      .fontSize(8.5)
      .fillColor(C.black)
      .font("Helvetica-Bold")
      .text(safe(f.checkName), cols.check.x + 4, y + 11, {
        width: cols.check.w - 6,
      })
      .restore();

    badge(
      f.passed ? "PASS" : "FAIL",
      cols.status.x + 4,
      y + 6,
      38,
      f.passed ? C.green : C.red,
      f.passed ? C.greenlt : C.redlt,
    );

    const sev = SEV[f.severity] || SEV["None"];
    badge(
      safe(f.severity).toUpperCase(),
      cols.severity.x + 2,
      y + 6,
      50,
      sev.fg,
      sev.bg,
    );

    fill(cols.owasp.x + 2, y + 5, cols.owasp.w - 6, 20, C.primarylt);
    strokeBox(cols.owasp.x + 2, y + 5, cols.owasp.w - 6, 20, C.primary);
    doc
      .save()
      .fontSize(6.5)
      .fillColor(C.primary)
      .font("Helvetica")
      .text(safe(f.owasp || "N/A"), cols.owasp.x + 5, y + 11, {
        width: cols.owasp.w - 10,
      })
      .restore();

    doc
      .save()
      .fontSize(10)
      .fillColor(f.weight > 0 ? C.red : C.gray)
      .font("Helvetica-Bold")
      .text(f.weight > 0 ? `-${f.weight}` : "0", cols.penalty.x, y + 10, {
        width: cols.penalty.w,
        align: "center",
      })
      .restore();

    y += rowH;
    hr(y, C.border, 0.5);
  });

  // Footer on findings page → then new page
  drawFooter();
  doc.addPage();

  // ================================================================
  // PAGE 3 — REMEDIATION
  // ================================================================
  fill(0, 0, PW, 8, C.primary);
  y = sectionTitle("Remediation Recommendations", 20);

  doc
    .save()
    .fontSize(9)
    .fillColor(C.gray)
    .font("Helvetica")
    .text("Actionable fixes mapped to OWASP API Security Top 10 (2023)", L, y)
    .restore();
  y += 20;

  const failedFindings = scan.findings.filter((f) => !f.passed);

  if (failedFindings.length === 0) {
    fill(L, y, W, 50, C.greenlt);
    strokeBox(L, y, W, 50, C.green);
    doc
      .save()
      .fontSize(12)
      .fillColor(C.green)
      .font("Helvetica-Bold")
      .text("All checks passed — no remediation required.", L, y + 18, {
        width: W,
        align: "center",
      })
      .restore();
  } else {
    failedFindings.forEach((f) => {
      const sev = SEV[f.severity] || SEV["None"];
      const detText = safe(f.detail);
      const remText = safe(f.remediation || "Review this finding manually.");

      const detLines = Math.ceil(detText.length / 88) + 1;
      const remLines = Math.ceil(remText.length / 88) + 1;
      const blockH = 32 + detLines * 13 + remLines * 13 + 28;

      if (y + blockH > CONTENT_BOTTOM) {
        drawFooter();
        doc.addPage();
        fill(0, 0, PW, 8, C.primary);
        y = 20;
      }

      fill(L, y, W, blockH, C.white);
      strokeBox(L, y, W, blockH, C.border);
      fill(L, y, 4, blockH, sev.fg);
      fill(L + 4, y, W - 4, 26, sev.bg);

      doc
        .save()
        .fontSize(10)
        .fillColor(sev.fg)
        .font("Helvetica-Bold")
        .text(safe(f.checkName), L + 12, y + 8, { width: 160 })
        .restore();

      badge(
        safe(f.severity).toUpperCase(),
        L + 180,
        y + 5,
        55,
        sev.fg,
        C.white,
      );

      fill(L + 242, y + 5, 165, 17, C.primarylt);
      strokeBox(L + 242, y + 5, 165, 17, C.primary);
      doc
        .save()
        .fontSize(7)
        .fillColor(C.primary)
        .font("Helvetica")
        .text(safe(f.owasp || "N/A"), L + 245, y + 9, { width: 159 })
        .restore();

      let innerY = y + 32;

      doc
        .save()
        .fontSize(8)
        .fillColor(C.gray)
        .font("Helvetica-Bold")
        .text("FINDING:", L + 12, innerY)
        .restore();
      innerY += 12;
      doc
        .save()
        .fontSize(8.5)
        .fillColor(C.darkgray)
        .font("Helvetica")
        .text(detText, L + 12, innerY, { width: W - 24, lineGap: 2 })
        .restore();
      innerY += detLines * 13 + 4;

      doc
        .save()
        .fontSize(8)
        .fillColor(C.primary)
        .font("Helvetica-Bold")
        .text("REMEDIATION:", L + 12, innerY)
        .restore();
      innerY += 12;
      doc
        .save()
        .fontSize(8.5)
        .fillColor(C.darkgray)
        .font("Helvetica")
        .text(remText, L + 12, innerY, { width: W - 24, lineGap: 2 })
        .restore();

      y += blockH + 12;
    });
  }

  // Footer on remediation page → then new page
  drawFooter();
  doc.addPage();

  // ================================================================
  // PAGE 4 — SCORE BREAKDOWN
  // ================================================================
  fill(0, 0, PW, 8, C.primary);
  y = sectionTitle("Risk Score Breakdown", 20);

  fill(L, y, W, 36, C.primarylt);
  strokeBox(L, y, W, 36, C.primary);
  doc
    .save()
    .fontSize(9.5)
    .fillColor(C.primary)
    .font("Helvetica-Bold")
    .text(
      "Score Formula:  Base Score (100)  -  Sum of all penalty weights  =  Final Score",
      L + 12,
      y + 13,
      { width: W - 24, align: "center" },
    )
    .restore();
  y += 50;

  fill(L, y, W, 60, scoreBg(scoreVal));
  strokeBox(L, y, W, 60, scoreColor(scoreVal));
  doc
    .save()
    .fontSize(36)
    .fillColor(scoreColor(scoreVal))
    .font("Helvetica-Bold")
    .text(`${scoreVal} / 100`, L, y + 10, { width: W, align: "center" })
    .restore();
  doc
    .save()
    .fontSize(12)
    .fillColor(scoreColor(scoreVal))
    .font("Helvetica")
    .text(safe(scan.severity), L, y + 47, { width: W, align: "center" })
    .restore();
  y += 75;

  fill(L, y, W, 24, C.lightgray);
  fill(L, y, Math.round(W * (scoreVal / 100)), 24, scoreColor(scoreVal));
  doc
    .save()
    .fontSize(8)
    .fillColor(C.white)
    .font("Helvetica-Bold")
    .text(`${scoreVal}%`, L + 6, y + 7)
    .restore();
  y += 32;

  scales.forEach(([range, label, fg], i) => {
    const sx = L + i * (W / 5);
    doc
      .save()
      .fontSize(6.5)
      .fillColor(fg)
      .font("Helvetica-Bold")
      .text(range, sx, y, { width: W / 5, align: "center" })
      .restore();
    doc
      .save()
      .fontSize(6)
      .fillColor(fg)
      .font("Helvetica")
      .text(label, sx, y + 8, { width: W / 5, align: "center" })
      .restore();
  });
  y += 30;

  doc
    .save()
    .fontSize(10)
    .fillColor(C.darkgray)
    .font("Helvetica-Bold")
    .text("Per-Check Penalty Breakdown", L, y)
    .restore();
  y += 18;

  fill(L, y, W, 22, C.darkgray);
  doc
    .save()
    .fontSize(8)
    .fillColor(C.white)
    .font("Helvetica-Bold")
    .text("Security Check", L + 8, y + 7, { width: 180 })
    .text("Result", L + 195, y + 7, { width: 60 })
    .text("Severity", L + 260, y + 7, { width: 70 })
    .text("Penalty", L + 330, y + 7, { width: 55 })
    .text("Running Score", L + 390, y + 7, { width: 80 })
    .restore();
  y += 22;

  let runningScore = 100;

  scan.findings.forEach((f, i) => {
    const rowH = 24;
    const rowBg = i % 2 === 0 ? C.white : C.lightgray;
    const sev = SEV[f.severity] || SEV["None"];

    fill(L, y, W, rowH, rowBg);
    fill(L, y, 3, rowH, f.passed ? C.green : sev.fg);

    doc
      .save()
      .fontSize(8.5)
      .fillColor(C.black)
      .font("Helvetica-Bold")
      .text(safe(f.checkName), L + 8, y + 7, { width: 180 })
      .restore();
    doc
      .save()
      .fontSize(8)
      .fillColor(f.passed ? C.green : C.red)
      .font("Helvetica-Bold")
      .text(f.passed ? "PASSED" : "FAILED", L + 195, y + 7, { width: 60 })
      .restore();
    doc
      .save()
      .fontSize(8)
      .fillColor(sev.fg)
      .font("Helvetica")
      .text(safe(f.severity), L + 260, y + 7, { width: 70 })
      .restore();

    if (!f.passed) runningScore = Math.max(0, runningScore - f.weight);

    doc
      .save()
      .fontSize(8)
      .fillColor(f.weight > 0 ? C.red : C.gray)
      .font("Helvetica-Bold")
      .text(f.weight > 0 ? `-${f.weight} pts` : "none", L + 330, y + 7, {
        width: 55,
      })
      .restore();
    doc
      .save()
      .fontSize(9)
      .fillColor(scoreColor(runningScore))
      .font("Helvetica-Bold")
      .text(runningScore.toString(), L + 390, y + 7, {
        width: 80,
        align: "center",
      })
      .restore();

    y += rowH;
    hr(y, C.border, 0.5);
  });

  y += 5;
  fill(L, y, W, 30, C.darkgray);
  doc
    .save()
    .fontSize(10)
    .fillColor(C.white)
    .font("Helvetica-Bold")
    .text("FINAL POSTURE SCORE", L + 8, y + 9, { width: 240 })
    .restore();
  doc
    .save()
    .fontSize(14)
    .fillColor(scoreColor(scoreVal))
    .font("Helvetica-Bold")
    .text(`${scoreVal} / 100 — ${safe(scan.severity)}`, L + 240, y + 7, {
      width: W - 250,
      align: "right",
    })
    .restore();

  // Footer on last page — no addPage after this
  drawFooter();

  doc.end();
};

module.exports = { generatePDFReport };
