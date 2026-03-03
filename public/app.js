// public/app.js — APIFortify v2.0

const DEFAULT_API_BASE =
  window.location.origin && window.location.origin.startsWith("http")
    ? `${window.location.origin}/api`
    : "http://localhost:5000/api";

const API_BASE = window.__API_BASE__ || DEFAULT_API_BASE;
const HEALTH_URL = API_BASE.replace(/\/api\/?$/, "") + "/health";

let currentScan = null;

document.addEventListener("DOMContentLoaded", () => {
  checkServerStatus();
  loadDashboardSummary();
  loadHistory();
  loadSeverityChart();
  loadCommonFindings();

  document.getElementById("targetInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") startScan();
  });
});

const checkServerStatus = async () => {
  const dot = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  const badge = document.querySelector(".nav-status");

  try {
    const response = await fetch(HEALTH_URL);
    if (!response.ok) throw new Error("Health endpoint unavailable");

    dot.className = "status-dot online";
    text.textContent = "Server Online";
    badge.classList.remove("offline");
    badge.classList.add("online");
  } catch {
    dot.className = "status-dot offline";
    text.textContent = "Server Offline";
    badge.classList.remove("online");
    badge.classList.add("offline");
  }
};

const loadDashboardSummary = async () => {
  try {
    const response = await fetch(`${API_BASE}/stats/summary`);
    const payload = await response.json();
    if (!payload.success) return;

    const { summary, uniqueTargetsCount } = payload.data;

    document.getElementById("totalScans").textContent = summary.totalScans ?? 0;
    document.getElementById("uniqueTargets").textContent =
      uniqueTargetsCount ?? 0;
    document.getElementById("avgScore").textContent = summary.avgScore ?? 0;
    document.getElementById("minScore").textContent = summary.minScore ?? 0;
  } catch (error) {
    console.error("Summary load failed:", error);
  }
};

const startScan = async () => {
  const target = document.getElementById("targetInput").value.trim();
  const endpoint = document.getElementById("endpointInput").value.trim();
  const token = document.getElementById("tokenInput").value.trim();
  const errorEl = document.getElementById("formError");

  errorEl.textContent = "";

  if (!target) {
    errorEl.textContent = "⚠ Target URL is required.";
    return;
  }

  if (!/^https?:\/\/.+/i.test(target)) {
    errorEl.textContent = "⚠ URL must start with http:// or https://";
    return;
  }

  showProgress(true);
  setButtonLoading(true);
  document.getElementById("resultSection").style.display = "none";

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        endpoint: endpoint || "/",
        token: token || undefined,
      }),
    });

    const payload = await response.json();

    if (!payload.success) {
      errorEl.textContent = `⚠ ${payload.message}`;
      return;
    }

    currentScan = payload.data;
    renderResult(payload.data);

    loadDashboardSummary();
    loadHistory();
    loadSeverityChart();
    loadCommonFindings();
  } catch {
    errorEl.textContent = "⚠ Could not connect to server. Is it running?";
  } finally {
    showProgress(false);
    setButtonLoading(false);
  }
};

const renderResult = (scan) => {
  currentScan = scan;

  const section = document.getElementById("resultSection");
  section.style.display = "block";
  section.scrollIntoView({ behavior: "smooth", block: "start" });

  const scoreCircle = document.getElementById("scoreCircle");
  document.getElementById("scoreNumber").textContent = scan.overallScore;
  scoreCircle.className = `score-circle ${getScoreClass(scan.overallScore)}`;

  const badge = document.getElementById("severityBadge");
  badge.textContent = scan.severity;
  badge.className = `severity-badge ${getBadgeClass(scan.severity)}`;

  document.getElementById("resultTarget").textContent =
    `Target: ${scan.target}${scan.endpoint !== "/" ? scan.endpoint : ""}`;
  document.getElementById("resultDuration").textContent =
    `Duration: ${(scan.scanDuration / 1000).toFixed(2)}s`;
  document.getElementById("resultTimestamp").textContent =
    `Scanned: ${new Date(scan.createdAt).toLocaleString()}`;

  const passed = scan.findings.filter((finding) => finding.passed).length;
  const failed = scan.findings.length - passed;

  document.getElementById("resultChecks").innerHTML =
    `<span class="checks-pass">✓ ${passed} passed</span>` +
    `&nbsp;&nbsp;<span class="checks-fail">✗ ${failed} failed</span>` +
    `&nbsp;&nbsp;out of ${scan.findings.length} checks`;

  const tbody = document.getElementById("findingsBody");
  tbody.innerHTML = "";

  scan.findings.forEach((finding) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${formatCheckName(finding.checkName)}</td>
      <td>
        <span class="pill ${finding.passed ? "pill-pass" : "pill-fail"}">
          ${finding.passed ? "✓ Pass" : "✗ Fail"}
        </span>
      </td>
      <td><span class="sev-${finding.severity.toLowerCase()}">${finding.severity}</span></td>
      <td><span class="owasp-tag">${escHtml(finding.owasp || "N/A")}</span></td>
      <td>${escHtml(finding.detail)}</td>
      <td class="weight-cell">${finding.weight > 0 ? `-${finding.weight}` : "0"}</td>
    `;
    tbody.appendChild(row);
  });

  const remediationList = document.getElementById("remediationList");
  const failedFindings = scan.findings.filter(
    (finding) => !finding.passed && finding.remediation,
  );

  if (failedFindings.length === 0) {
    remediationList.innerHTML =
      '<div class="empty-state"><div class="empty-title">No remediations needed</div><div class="empty-subtext">All security checks passed in this scan.</div></div>';
    return;
  }

  remediationList.innerHTML = failedFindings
    .map(
      (finding) => `
      <div class="remediation-item sev-${finding.severity.toLowerCase()}">
        <div class="remediation-header">
          <span class="remediation-check">${escHtml(finding.checkName)}</span>
          <span class="pill pill-fail sev-${finding.severity.toLowerCase()}">${finding.severity}</span>
          <span class="owasp-tag">${escHtml(finding.owasp || "N/A")}</span>
        </div>
        <div class="remediation-text">${escHtml(finding.remediation)}</div>
      </div>
    `,
    )
    .join("");
};

const downloadPDF = () => {
  if (!currentScan) return;

  const url = `${API_BASE}/report/${currentScan._id}/pdf`;
  const link = document.createElement("a");
  link.href = url;
  link.target = "_blank";
  link.click();
};

const exportReport = () => {
  if (!currentScan) return;

  const report = {
    reportTitle: "APIFortify Security Assessment Report",
    generatedAt: new Date().toISOString(),
    tool: "APIFortify v2.0",
    owaspCoverage: "OWASP API Security Top 10 (2023)",
    target: currentScan.target,
    endpoint: currentScan.endpoint,
    fullUrl: currentScan.fullUrl,
    scanDate: currentScan.createdAt,
    scanDuration: `${(currentScan.scanDuration / 1000).toFixed(2)}s`,
    overallScore: currentScan.overallScore,
    severity: currentScan.severity,
    summary: {
      totalChecks: currentScan.findings.length,
      passed: currentScan.findings.filter((finding) => finding.passed).length,
      failed: currentScan.findings.filter((finding) => !finding.passed).length,
    },
    findings: currentScan.findings,
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `apifortify-report-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
};

const loadHistory = async () => {
  const listEl = document.getElementById("historyList");
  listEl.innerHTML =
    '<div class="empty-state"><div class="empty-emoji">⏳</div><div class="empty-title">Loading scan history</div><div class="empty-subtext">Fetching your most recent scan entries.</div></div>';

  try {
    const response = await fetch(`${API_BASE}/scans?limit=10`);
    const payload = await response.json();

    if (!payload.success || payload.data.length === 0) {
      listEl.innerHTML =
        '<div class="empty-state"><div class="empty-emoji">📭</div><div class="empty-title">No scans yet</div><div class="empty-subtext">Start a scan above to create your first history record.</div></div>';
      return;
    }

    listEl.innerHTML = `
      <div class="history-table-head">
        <div>Target</div>
        <div>Risk Level</div>
        <div>Date</div>
        <div>Score</div>
      </div>
    `;

    payload.data.forEach((scan) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "history-row";
      row.onclick = () => loadScanDetail(scan._id);

      row.innerHTML = `
        <div>
          <div class="history-target" title="${escHtml(scan.target)}">${escHtml(scan.target)}</div>
          <div class="history-meta">${scan.endpoint !== "/" ? escHtml(scan.endpoint) : "Root endpoint"}</div>
        </div>
        <div><span class="risk-pill ${getSeverityPillClass(scan.severity)}">${escHtml(scan.severity)}</span></div>
        <div class="history-date">${new Date(scan.createdAt).toLocaleDateString()}</div>
        <div class="history-score" style="color:${getScoreColor(scan.overallScore)}">${scan.overallScore}</div>
      `;

      listEl.appendChild(row);
    });
  } catch {
    listEl.innerHTML =
      '<div class="empty-state"><div class="empty-emoji">⚠️</div><div class="empty-title">Could not load scan history</div><div class="empty-subtext">Please refresh or verify the API server status.</div></div>';
  }
};

const loadScanDetail = async (id) => {
  try {
    const response = await fetch(`${API_BASE}/scans/${id}`);
    const payload = await response.json();

    if (payload.success) {
      renderResult(payload.data);
      document
        .getElementById("resultSection")
        .scrollIntoView({ behavior: "smooth" });
    }
  } catch (error) {
    console.error("Detail load failed:", error);
  }
};

const loadSeverityChart = async () => {
  const chartEl = document.getElementById("severityChart");

  try {
    const response = await fetch(`${API_BASE}/stats/severity`);
    const payload = await response.json();

    if (!payload.success || payload.data.length === 0) {
      chartEl.innerHTML =
        '<div class="empty-state"><div class="empty-emoji">📊</div><div class="empty-title">No severity data yet</div><div class="empty-subtext">Run scans to see distribution trends.</div></div>';
      return;
    }

    const max = Math.max(...payload.data.map((item) => item.count));

    const colors = {
      Secure: "var(--green)",
      "Low Risk": "#86efac",
      "Medium Risk": "var(--yellow)",
      "High Risk": "var(--orange)",
      Critical: "var(--critical)",
    };

    const icons = {
      Critical: "⛔",
      "High Risk": "⚠",
    };

    chartEl.innerHTML = payload.data
      .map((item) => {
        const percent = max > 0 ? (item.count / max) * 100 : 0;
        const color = colors[item.severity] || "var(--primary)";
        const icon = icons[item.severity] || "";

        return `
          <div class="sev-bar-row">
            <div class="sev-bar-label">${icon ? `<span class="sev-icon">${icon}</span>` : ""}${escHtml(item.severity)}</div>
            <div class="sev-bar-track">
              <div class="sev-bar-fill" style="width:${percent}%;background:${color};"></div>
            </div>
            <div class="sev-bar-count">${item.count}</div>
          </div>
        `;
      })
      .join("");
  } catch {
    chartEl.innerHTML =
      '<div class="empty-state"><div class="empty-emoji">⚠️</div><div class="empty-title">Failed to load severity chart</div><div class="empty-subtext">Please try again in a moment.</div></div>';
  }
};

const loadCommonFindings = async () => {
  const el = document.getElementById("commonFindings");

  try {
    const response = await fetch(`${API_BASE}/stats/findings`);
    const payload = await response.json();

    if (!payload.success || payload.data.length === 0) {
      el.innerHTML =
        '<div class="empty-state"><div class="empty-emoji">🧩</div><div class="empty-title">No failed checks yet</div><div class="empty-subtext">Common findings will appear after more scans.</div></div>';
      return;
    }

    el.innerHTML = payload.data
      .map(
        (item) => `
        <div class="finding-row">
          <span class="finding-name">${escHtml(item.checkName)}</span>
          <span class="finding-count">${item.failCount} fails</span>
        </div>
      `,
      )
      .join("");
  } catch {
    el.innerHTML =
      '<div class="empty-state"><div class="empty-emoji">⚠️</div><div class="empty-title">Failed to load findings</div><div class="empty-subtext">Please refresh or check server connectivity.</div></div>';
  }
};

const showProgress = (show) => {
  document.getElementById("progressSection").style.display = show
    ? "block"
    : "none";
};

const setButtonLoading = (loading) => {
  const button = document.getElementById("scanBtn");
  button.disabled = loading;
  button.classList.toggle("is-loading", loading);

  document.getElementById("scanBtnText").textContent = loading
    ? "Scanning..."
    : "Run Security Scan";
};

const getScoreClass = (score) => {
  if (score >= 90) return "score-secure";
  if (score >= 70) return "score-low";
  if (score >= 50) return "score-medium";
  if (score >= 25) return "score-high";
  return "score-critical";
};

const getBadgeClass = (severity) =>
  (
    {
      Secure: "badge-secure",
      "Low Risk": "badge-low",
      "Medium Risk": "badge-medium",
      "High Risk": "badge-high",
      Critical: "badge-critical",
    }
  )[severity] || "badge-medium";

const getSeverityPillClass = (severity) =>
  (
    {
      Secure: "risk-secure",
      "Low Risk": "risk-low",
      "Medium Risk": "risk-medium",
      "High Risk": "risk-high",
      Critical: "risk-critical",
    }
  )[severity] || "risk-medium";

const getScoreColor = (score) => {
  if (score >= 90) return "var(--green)";
  if (score >= 70) return "#86efac";
  if (score >= 50) return "var(--yellow)";
  if (score >= 25) return "var(--orange)";
  return "var(--critical)";
};

const formatCheckName = (checkName) => {
  const name = checkName || "";
  const tips = [];

  if (/BOLA/i.test(name)) {
    tips.push(
      '<span class="term-tip" title="BOLA: Broken Object Level Authorization. Attackers can access other users\' objects by manipulating identifiers.">BOLA</span>',
    );
  }

  if (/CORS/i.test(name)) {
    tips.push(
      '<span class="term-tip" title="CORS: Cross-Origin Resource Sharing. Misconfiguration can expose APIs to unauthorized browser origins.">CORS</span>',
    );
  }

  const tipsHtml = tips.length
    ? `<span class="term-tip-wrap">${tips.join("")}</span>`
    : "";

  return `<strong>${escHtml(name)}</strong>${tipsHtml}`;
};

const escHtml = (value) => {
  if (!value) return "";

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
};
