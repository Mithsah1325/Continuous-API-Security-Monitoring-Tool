// services/scanner.js
// APIFortify — Security Scanner Module
// Performs 9 automated security checks against a target API.
//
// Each check returns a finding object:
// {
//   checkName   : string
//   passed      : boolean
//   detail      : string   — what was found
//   severity    : string   — None | Low | Medium | High | Critical
//   weight      : number   — penalty for risk engine
//   owasp       : string   — OWASP API Top 10 (2023) category
//   remediation : string   — how to fix it
// }

const axios = require("axios");

const httpClient = axios.create({
  timeout: 10000,
  validateStatus: () => true,
});

const buildUrl = (target, endpoint) => {
  const base = target.replace(/\/$/, "");
  const ep = endpoint && endpoint !== "/" ? endpoint : "";
  return `${base}${ep}`;
};

const buildHeaders = (token) => {
  const headers = {
    "User-Agent": "APIFortify-Scanner/2.0",
    Accept: "application/json, text/plain, */*",
  };
  if (token) {
    const normalizedToken = token.replace(/^Bearer\s+/i, "").trim();
    if (normalizedToken) {
      headers["Authorization"] = `Bearer ${normalizedToken}`;
    }
  }
  return headers;
};

// =================================================================
// CHECK 1: SECURITY HEADERS
// OWASP: API8:2023 - Security Misconfiguration
// =================================================================
const runHeaderCheck = async (target, endpoint, token) => {
  const checkName = "Security Headers";
  const owasp = "API8:2023 - Security Misconfiguration";

  try {
    const url = buildUrl(target, endpoint);
    const response = await httpClient.get(url, {
      headers: buildHeaders(token),
    });

    const required = [
      "content-security-policy",
      "strict-transport-security",
      "x-frame-options",
      "x-content-type-options",
    ];

    const missing = required.filter((h) => !response.headers[h]);

    if (missing.length === 0) {
      return {
        checkName,
        passed: true,
        detail: "All required security headers are present.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    const severity = missing.length >= 3 ? "High" : "Medium";
    const weight = severity === "High" ? 15 : 8;

    return {
      checkName,
      passed: false,
      detail: `Missing security headers: ${missing.join(", ")}`,
      severity,
      weight,
      owasp,
      remediation:
        "Add the missing headers in your server/framework configuration. " +
        "For Express: use the `helmet` npm package — it sets all security headers automatically with one line: app.use(helmet()). " +
        "For Nginx: add headers in the server block. For Apache: use mod_headers.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable and the URL is correct.",
    };
  }
};

// =================================================================
// CHECK 2: CORS MISCONFIGURATION
// OWASP: API8:2023 - Security Misconfiguration
// =================================================================
const runCorsCheck = async (target, endpoint, token) => {
  const checkName = "CORS Configuration";
  const owasp = "API8:2023 - Security Misconfiguration";

  try {
    const url = buildUrl(target, endpoint);
    const response = await httpClient.get(url, {
      headers: { ...buildHeaders(token), Origin: "https://evil-attacker.com" },
    });

    const acao = response.headers["access-control-allow-origin"];
    const acac = response.headers["access-control-allow-credentials"];

    if (!acao) {
      return {
        checkName,
        passed: true,
        detail:
          "No CORS headers. API does not allow cross-origin access by default.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    if (acao === "*" && acac === "true") {
      return {
        checkName,
        passed: false,
        detail:
          "Critical CORS misconfiguration: wildcard origin + credentials allowed. Any site can make authenticated requests.",
        severity: "Critical",
        weight: 25,
        owasp,
        remediation:
          "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. " +
          "Define an explicit allowlist of trusted origins. Use environment variables to manage origins per deployment.",
      };
    }

    if (acao === "*") {
      return {
        checkName,
        passed: false,
        detail:
          "CORS wildcard (Access-Control-Allow-Origin: *). Any website can read API responses.",
        severity: "Medium",
        weight: 8,
        owasp,
        remediation:
          "Replace the wildcard with an explicit origin allowlist. " +
          "Example in Express: cors({ origin: ['https://yourapp.com'] }). " +
          "For public read-only APIs, wildcard may be acceptable — evaluate based on data sensitivity.",
      };
    }

    if (acao === "https://evil-attacker.com") {
      return {
        checkName,
        passed: false,
        detail:
          "CORS origin reflection detected. Server mirrors any Origin header — any domain can access this API.",
        severity: "High",
        weight: 15,
        owasp,
        remediation:
          "Maintain a static allowlist of permitted origins. " +
          "Never reflect the Origin header value back directly. " +
          "Validate origins against the allowlist before setting the response header.",
      };
    }

    return {
      checkName,
      passed: true,
      detail: `CORS restricted to specific origin: ${acao}`,
      severity: "None",
      weight: 0,
      owasp,
      remediation: "No action required.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 3: HTTP METHOD EXPOSURE
// OWASP: API8:2023 - Security Misconfiguration
// =================================================================
const runMethodCheck = async (target, endpoint, token) => {
  const checkName = "HTTP Method Exposure";
  const owasp = "API8:2023 - Security Misconfiguration";

  try {
    const url = buildUrl(target, endpoint);
    const response = await httpClient.options(url, {
      headers: buildHeaders(token),
    });

    const allowHeader =
      response.headers["allow"] ||
      response.headers["access-control-allow-methods"] ||
      "";

    if (!allowHeader) {
      return {
        checkName,
        passed: true,
        detail:
          "No Allow header returned. Method exposure cannot be determined — generally safe.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    const dangerous = ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"];
    const allowed = allowHeader.split(",").map((m) => m.trim().toUpperCase());
    const exposed = dangerous.filter((m) => allowed.includes(m));

    if (exposed.includes("TRACE")) {
      return {
        checkName,
        passed: false,
        detail: `Dangerous methods exposed including TRACE: ${exposed.join(", ")}. TRACE enables Cross-Site Tracing (XST) attacks.`,
        severity: "High",
        weight: 15,
        owasp,
        remediation:
          "Disable TRACE method at the web server level. " +
          "In Nginx: add `limit_except GET POST { deny all; }`. " +
          "In Apache: add `TraceEnable off` to httpd.conf. " +
          "Only expose HTTP methods your API actually uses.",
      };
    }

    if (exposed.length > 0) {
      return {
        checkName,
        passed: false,
        detail: `Potentially dangerous HTTP methods exposed: ${exposed.join(", ")}`,
        severity: "Medium",
        weight: 8,
        owasp,
        remediation:
          "Audit which HTTP methods your API actually requires. " +
          "Disable all others at the framework or server level. " +
          "In Express, define routes only for required methods — do not use app.all().",
      };
    }

    return {
      checkName,
      passed: true,
      detail: `Only safe methods exposed: ${allowed.join(", ")}`,
      severity: "None",
      weight: 0,
      owasp,
      remediation: "No action required.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 4: SERVER INFORMATION LEAKAGE
// OWASP: API8:2023 - Security Misconfiguration
// =================================================================
const runServerLeakageCheck = async (target, endpoint, token) => {
  const checkName = "Server Information Leakage";
  const owasp = "API8:2023 - Security Misconfiguration";

  try {
    const url = buildUrl(target, endpoint);
    const response = await httpClient.get(url, {
      headers: buildHeaders(token),
    });
    const leaky = [];

    const serverHeader = response.headers["server"];
    if (
      serverHeader &&
      (/[\d]+\.[\d]/.test(serverHeader) || serverHeader.length > 20)
    ) {
      leaky.push(`Server: ${serverHeader}`);
    }

    const poweredBy = response.headers["x-powered-by"];
    if (poweredBy) leaky.push(`X-Powered-By: ${poweredBy}`);

    const aspNet = response.headers["x-aspnet-version"];
    const aspMvc = response.headers["x-aspnetmvc-version"];
    if (aspNet) leaky.push(`X-AspNet-Version: ${aspNet}`);
    if (aspMvc) leaky.push(`X-AspNetMvc-Version: ${aspMvc}`);

    if (leaky.length === 0) {
      return {
        checkName,
        passed: true,
        detail: "No sensitive server information found in response headers.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    return {
      checkName,
      passed: false,
      detail: `Technology stack exposed in headers: ${leaky.join(" | ")}`,
      severity: "Medium",
      weight: 8,
      owasp,
      remediation:
        "Remove or obscure version-revealing headers. " +
        "In Express: app.disable('x-powered-by') or use helmet(). " +
        "In Nginx: set server_tokens off in nginx.conf. " +
        "In Apache: set ServerTokens Prod and ServerSignature Off.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 5: ERROR HANDLING VERBOSITY
// OWASP: API8:2023 - Security Misconfiguration
// =================================================================
const runErrorHandlingCheck = async (target, endpoint, token) => {
  const checkName = "Error Handling Verbosity";
  const owasp = "API8:2023 - Security Misconfiguration";

  try {
    const base = target.replace(/\/$/, "");
    const errorUrl = `${base}/apifortify-probe-${Date.now()}`;
    const response = await httpClient.get(errorUrl, {
      headers: buildHeaders(token),
    });

    if (response.status === 200) {
      return {
        checkName,
        passed: true,
        detail:
          "Server returned 200 for unknown path — likely catch-all routing. No error details exposed.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    const body =
      typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data || "");

    const patterns = [
      { pattern: /at\s+\w+\s+\(.*:\d+:\d+\)/i, label: "stack trace" },
      { pattern: /stacktrace|stack_trace/i, label: "stack trace key" },
      {
        pattern: /MongoError|mongoose|mongodb/i,
        label: "database error detail",
      },
      {
        pattern: /SyntaxError|ReferenceError|TypeError/i,
        label: "JS error type",
      },
      { pattern: /node_modules/i, label: "internal file path" },
      { pattern: /sql|sqlite|mysql|postgresql/i, label: "SQL error detail" },
      {
        pattern: /password|secret|api_key|apikey/i,
        label: "possible credential",
      },
    ];

    const found = patterns
      .filter(({ pattern }) => pattern.test(body))
      .map(({ label }) => label);

    if (found.length === 0) {
      return {
        checkName,
        passed: true,
        detail: `Error responses are clean. No sensitive details in ${response.status} response.`,
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    if (found.includes("possible credential")) {
      return {
        checkName,
        passed: false,
        detail: `Critical: Error response may contain credentials. Found: ${found.join(", ")}`,
        severity: "Critical",
        weight: 25,
        owasp,
        remediation:
          "Immediately audit what your error handler returns. " +
          "Never include request objects, environment variables, or config in error responses. " +
          "Use a global error handler that returns only a generic message and a correlation ID.",
      };
    }

    return {
      checkName,
      passed: false,
      detail: `Verbose error response detected. Exposed: ${found.join(", ")}`,
      severity: "High",
      weight: 15,
      owasp,
      remediation:
        "Implement a global error handler that returns generic messages in production. " +
        "Log full error details server-side only. " +
        "In Express: use a centralized error middleware — never let raw errors reach the client. " +
        "Set NODE_ENV=production to suppress framework-level error details.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 6: ID ENUMERATION / BOLA
// OWASP: API1:2023 - Broken Object Level Authorization
// =================================================================
const runIdEnumerationCheck = async (target, endpoint, token) => {
  const checkName = "ID Enumeration (BOLA)";
  const owasp = "API1:2023 - Broken Object Level Authorization";

  try {
    const base = target.replace(/\/$/, "");
    const hasNumericId = /\/\d+/.test(endpoint || "");

    const testPaths = hasNumericId
      ? [endpoint.replace(/\/\d+/, "/1"), endpoint.replace(/\/\d+/, "/99999")]
      : ["/1", "/99999"];

    const [res1, res2] = await Promise.all([
      httpClient.get(`${base}${testPaths[0]}`, {
        headers: buildHeaders(token),
      }),
      httpClient.get(`${base}${testPaths[1]}`, {
        headers: buildHeaders(token),
      }),
    ]);

    if (res1.status === res2.status) {
      return {
        checkName,
        passed: true,
        detail: `Both ID-based requests returned same status (${res1.status}). No obvious BOLA/enumeration vulnerability.`,
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    if (res1.status === 200 && (res2.status === 404 || res2.status === 403)) {
      return {
        checkName,
        passed: false,
        detail: `BOLA/ID enumeration risk: sequential IDs return different statuses (/1 → ${res1.status}, /99999 → ${res2.status}).`,
        severity: "Medium",
        weight: 8,
        owasp,
        remediation:
          "Replace sequential integer IDs with UUIDs (v4) to prevent enumeration. " +
          "Implement object-level authorization checks — verify the requesting user owns the resource. " +
          "Return 403 Forbidden (not 404) for unauthorized access to prevent confirming existence.",
      };
    }

    return {
      checkName,
      passed: true,
      detail: `ID requests returned statuses ${res1.status} and ${res2.status}. No clear enumeration pattern.`,
      severity: "None",
      weight: 0,
      owasp,
      remediation: "No action required.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 7: RATE LIMITING
// OWASP: API4:2023 - Unrestricted Resource Consumption
// =================================================================
const runRateLimitCheck = async (target, endpoint, token) => {
  const checkName = "Rate Limiting";
  const owasp = "API4:2023 - Unrestricted Resource Consumption";

  try {
    const url = buildUrl(target, endpoint);
    const response = await httpClient.get(url, {
      headers: buildHeaders(token),
    });

    const rlHeaders = [
      "ratelimit-limit",
      "ratelimit-remaining",
      "ratelimit-reset",
      "x-ratelimit-limit",
      "x-ratelimit-remaining",
      "x-ratelimit-reset",
      "retry-after",
      "x-rate-limit-limit",
    ];

    const found = rlHeaders.filter((h) => response.headers[h] !== undefined);

    if (response.status === 429) {
      return {
        checkName,
        passed: true,
        detail: "Rate limiting active — server returned 429 Too Many Requests.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    if (found.length > 0) {
      return {
        checkName,
        passed: true,
        detail: `Rate limiting headers detected: ${found.join(", ")}`,
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    return {
      checkName,
      passed: false,
      detail:
        "No rate limiting headers detected. API may be vulnerable to brute force, credential stuffing, and DoS.",
      severity: "Medium",
      weight: 8,
      owasp,
      remediation:
        "Implement rate limiting at the API gateway or application level. " +
        "In Express: use `express-rate-limit` middleware. " +
        "Apply stricter limits on authentication endpoints (login, password reset). " +
        "Return standard RateLimit-* headers so clients can self-throttle.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 8: AUTHENTICATION HEADER ANALYSIS
// OWASP: API2:2023 - Broken Authentication
// =================================================================
const runAuthCheck = async (target, endpoint, token) => {
  const checkName = "Authentication Mechanisms";
  const owasp = "API2:2023 - Broken Authentication";

  try {
    const url = buildUrl(target, endpoint);

    // First request: no auth
    const response = await httpClient.get(url, {
      headers: {
        "User-Agent": "APIFortify-Scanner/2.0",
        Accept: "application/json",
      },
    });

    const wwwAuth = response.headers["www-authenticate"];
    const hasAuthHeader = !!wwwAuth;

    // Check if unauthenticated request reaches sensitive-looking data
    const body =
      typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data || "");

    const sensitiveDataPatterns = [
      {
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i,
        label: "email addresses",
      },
      { pattern: /"password"\s*:/i, label: "password field" },
      { pattern: /"token"\s*:\s*"[^"]{20,}"/i, label: "token value" },
      { pattern: /"ssn"\s*:/i, label: "SSN field" },
      { pattern: /"credit_card"\s*:|"card_number"\s*:/i, label: "card data" },
    ];

    const foundSensitive = sensitiveDataPatterns
      .filter(({ pattern }) => pattern.test(body))
      .map(({ label }) => label);

    // Unauthenticated request returns 200 with sensitive data
    if (response.status === 200 && foundSensitive.length > 0) {
      return {
        checkName,
        passed: false,
        detail: `Unauthenticated request returned 200 with potentially sensitive data: ${foundSensitive.join(", ")}`,
        severity: "Critical",
        weight: 25,
        owasp,
        remediation:
          "Enforce authentication on all endpoints that return user or sensitive data. " +
          "Implement JWT or OAuth 2.0 with proper validation. " +
          "Use middleware to verify tokens before route handlers execute. " +
          "Audit all endpoints for authentication bypass vulnerabilities.",
      };
    }

    // 401 with WWW-Authenticate header — good practice
    if (response.status === 401 && hasAuthHeader) {
      return {
        checkName,
        passed: true,
        detail: `Endpoint properly requires authentication (401) with WWW-Authenticate: ${wwwAuth}`,
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    // 401 or 403 without auth challenge header
    if (response.status === 401 || response.status === 403) {
      return {
        checkName,
        passed: true,
        detail: `Endpoint requires authentication (${response.status}). Consider adding WWW-Authenticate header for clarity.`,
        severity: "None",
        weight: 0,
        owasp,
        remediation:
          "Add WWW-Authenticate header to 401 responses to indicate the expected auth scheme.",
      };
    }

    // 200 but no sensitive data found — could be a public endpoint
    if (response.status === 200 && foundSensitive.length === 0) {
      return {
        checkName,
        passed: true,
        detail:
          "Unauthenticated request returns 200 — endpoint appears to be public. No sensitive data detected in response.",
        severity: "None",
        weight: 0,
        owasp,
        remediation:
          "Verify this endpoint is intentionally public. If it should be protected, add authentication middleware.",
      };
    }

    return {
      checkName,
      passed: true,
      detail: `Endpoint returned ${response.status} for unauthenticated request. Authentication behavior appears controlled.`,
      severity: "None",
      weight: 0,
      owasp,
      remediation: "No action required.",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// CHECK 9: SENSITIVE DATA EXPOSURE IN RESPONSE
// OWASP: API3:2023 - Broken Object Property Level Authorization
// =================================================================
const runSensitiveDataCheck = async (target, endpoint, token) => {
  const checkName = "Sensitive Data Exposure";
  const owasp = "API3:2023 - Broken Object Property Level Authorization";

  try {
    const url = buildUrl(target, endpoint);
    const response = await httpClient.get(url, {
      headers: buildHeaders(token),
    });

    if (response.status >= 400) {
      return {
        checkName,
        passed: true,
        detail: `No response body to analyze (status: ${response.status}).`,
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    const body =
      typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data || "");

    const checks = [
      {
        pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
        label: "private key material",
        severity: "Critical",
        weight: 25,
      },
      {
        pattern: /"password"\s*:\s*"[^"]+"/i,
        label: "password field in response",
        severity: "Critical",
        weight: 25,
      },
      {
        pattern:
          /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
        label: "JWT token in response body",
        severity: "High",
        weight: 15,
      },
      {
        pattern: /(?:AKIA|ASIA|AROA)[A-Z0-9]{16}/,
        label: "AWS access key",
        severity: "Critical",
        weight: 25,
      },
      {
        pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b/,
        label: "credit card number pattern",
        severity: "Critical",
        weight: 25,
      },
      {
        pattern: /"ssn"\s*:|"social_security"\s*:/i,
        label: "SSN field",
        severity: "High",
        weight: 15,
      },
      {
        pattern:
          /"secret"\s*:\s*"[^"]+"|"api_key"\s*:\s*"[^"]+"|"apikey"\s*:\s*"[^"]+"/i,
        label: "API key or secret in response",
        severity: "High",
        weight: 15,
      },
    ];

    const found = checks.filter(({ pattern }) => pattern.test(body));

    if (found.length === 0) {
      return {
        checkName,
        passed: true,
        detail: "No sensitive data patterns detected in response body.",
        severity: "None",
        weight: 0,
        owasp,
        remediation: "No action required.",
      };
    }

    // Use the highest severity found
    const hasCritical = found.some((f) => f.severity === "Critical");
    const severity = hasCritical ? "Critical" : "High";
    const weight = hasCritical ? 25 : 15;
    const labels = found.map((f) => f.label).join(", ");

    return {
      checkName,
      passed: false,
      detail: `Sensitive data patterns found in response: ${labels}`,
      severity,
      weight,
      owasp,
      remediation:
        "Apply response filtering — only return fields the client needs (principle of least privilege). " +
        "Never include passwords, private keys, or secrets in API responses. " +
        "Use a DTO (Data Transfer Object) pattern to whitelist response fields. " +
        "Audit all API responses for data minimization compliance (GDPR, PCI-DSS).",
    };
  } catch (err) {
    return {
      checkName,
      passed: false,
      detail: `Check failed: ${err.message}`,
      severity: "Low",
      weight: 3,
      owasp,
      remediation: "Ensure the target is reachable.",
    };
  }
};

// =================================================================
// ORCHESTRATOR — Run all 9 checks in parallel
// =================================================================
const runAllChecks = async (target, endpoint, token) => {
  const results = await Promise.allSettled([
    runHeaderCheck(target, endpoint, token),
    runCorsCheck(target, endpoint, token),
    runMethodCheck(target, endpoint, token),
    runServerLeakageCheck(target, endpoint, token),
    runErrorHandlingCheck(target, endpoint, token),
    runIdEnumerationCheck(target, endpoint, token),
    runRateLimitCheck(target, endpoint, token),
    runAuthCheck(target, endpoint, token),
    runSensitiveDataCheck(target, endpoint, token),
  ]);

  const checkNames = [
    "Security Headers",
    "CORS Configuration",
    "HTTP Method Exposure",
    "Server Information Leakage",
    "Error Handling Verbosity",
    "ID Enumeration (BOLA)",
    "Rate Limiting",
    "Authentication Mechanisms",
    "Sensitive Data Exposure",
  ];

  return results.map((result, i) => {
    if (result.status === "fulfilled") return result.value;
    return {
      checkName: checkNames[i],
      passed: false,
      detail: `Check encountered an unexpected error: ${result.reason}`,
      severity: "Low",
      weight: 3,
      owasp: "N/A",
      remediation: "Review scanner logs for details.",
    };
  });
};

module.exports = { runAllChecks };
