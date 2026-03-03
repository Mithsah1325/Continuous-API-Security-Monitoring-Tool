# 🛡️ APIFortify

**On-Demand APIFortify – Open Source REST API Security Scanner (OWASP API Top 10)**

APIFortify is an automated security scanning tool that performs structured posture analysis of REST APIs against the **OWASP API Security Top 10 (2023)**. Point it at any API, and it runs 9 security checks in parallel, calculates a weighted risk score, maps every finding to an OWASP category, and delivers actionable remediation guidance — all backed by MongoDB and exportable as a professional PDF report.

---

## 🖥️ Dashboard Preview

> Real-time dashboard with scan history, severity distribution, and OWASP-mapped findings table.
<img width="1828" height="852" alt="Screenshot 2026-02-28 004340" src="https://github.com/user-attachments/assets/6d05de65-b81c-40c7-b9e7-e39bb2028057" />

## 🎥 Watch Full Demo

[![APIFortify Demo](https://img.youtube.com/vi/ejLG_pj9k_Y/0.jpg)](https://www.youtube.com/watch?v=ejLG_pj9k_Y)
---





## ✨ Features

- **9 Automated Security Checks** — runs in parallel, covers OWASP API Top 10 (2023)
- **Weighted Risk Scoring** — 0 to 100 posture score with severity classification
- **OWASP API Top 10 (2023) Mapping** — every finding tagged to its OWASP category
- **Remediation Recommendations** — actionable developer-facing fix guidance per finding
- **PDF Report Export** — professional 4-page PDF with cover, findings table, remediation cards, and score breakdown
- **JSON Report Export** — machine-readable output for pipeline integration
- **Scan History & Trend Analysis** — track posture changes across multiple scans per target
- **MongoDB Aggregation Pipelines** — severity distribution, most common failures, per-target history
- **Real-time Dashboard** — live stats, severity chart, scan history, one-click detail view
- **Auth Token Support** — scan protected endpoints using Bearer token injection

---

## 🔒 Security Checks

| #   | Check                      | OWASP Category                                         | Max Penalty |
| --- | -------------------------- | ------------------------------------------------------ | ----------- |
| 1   | Security Headers           | API8:2023 — Security Misconfiguration                  | -15         |
| 2   | CORS Configuration         | API8:2023 — Security Misconfiguration                  | -25         |
| 3   | HTTP Method Exposure       | API8:2023 — Security Misconfiguration                  | -15         |
| 4   | Server Information Leakage | API8:2023 — Security Misconfiguration                  | -8          |
| 5   | Error Handling Verbosity   | API8:2023 — Security Misconfiguration                  | -25         |
| 6   | ID Enumeration (BOLA)      | API1:2023 — Broken Object Level Authorization          | -8          |
| 7   | Rate Limiting              | API4:2023 — Unrestricted Resource Consumption          | -8          |
| 8   | Authentication Mechanisms  | API2:2023 — Broken Authentication                      | -25         |
| 9   | Sensitive Data Exposure    | API3:2023 — Broken Object Property Level Authorization | -25         |

---

## 📊 Risk Scoring Engine

```
Base Score : 100

Penalties per failed check:
  Critical  →  -25 pts
  High      →  -15 pts
  Medium    →   -8 pts
  Low       →   -3 pts

Final Score = max(0, 100 − Σ penalties)

Score Classification:
  90 – 100  →  Secure
  70 –  89  →  Low Risk
  50 –  69  →  Medium Risk
  25 –  49  →  High Risk
   0 –  24  →  Critical
```

---

## 📄 PDF Report — Pages

| Page | Content                                                                              |
| ---- | ------------------------------------------------------------------------------------ |
| 1    | Cover — score, severity, scan metadata, pass/fail summary, risk scale                |
| 2    | Security Check Findings — full OWASP-mapped table with status and penalties          |
| 3    | Remediation Recommendations — per-finding cards with finding detail and fix guidance |
| 4    | Risk Score Breakdown — formula, progress bar, per-check running score table          |

---

## 🗂️ Project Architecture

```
apifortify/
├── config/
│   └── db.js                   # MongoDB Atlas connection
├── controllers/
│   ├── scanController.js        # Scan CRUD — create, list, get, delete
│   ├── statsController.js       # MongoDB aggregation pipeline endpoints
│   └── reportController.js      # PDF report generation and streaming
├── models/
│   └── Scan.js                  # Mongoose schema, indexes, virtual fields
├── routes/
│   └── api.js                   # Express route definitions
├── services/
│   ├── scanner.js               # 9 parallel security check functions
│   ├── riskEngine.js            # Weighted scoring engine
│   └── reportGenerator.js       # PDFKit report generation
├── public/
│   ├── index.html               # Dashboard UI
│   ├── style.css                # Dark theme, responsive layout
│   └── app.js                   # Vanilla JS — fetch, rendering, export
├── .env                         # Environment config (not committed)
├── .gitignore
├── package.json
└── server.js                    # Express entry point
```

**Design pattern:** MVC + Service Layer. Controllers are thin — business logic lives in the service layer. The model handles only schema definition, indexing, and virtuals.

---

## 🍃 MongoDB Design Decisions

### Why Document Model Over Relational?

Each scan produces a variable-length array of findings. In a relational database this requires a separate `findings` table, foreign keys, and a JOIN on every read. In MongoDB, the complete scan result — all 9 nested findings — is one document. One write. One read. No joins.

### Schema

```javascript
ScanDocument {
  target        : String    // indexed for history lookups
  endpoint      : String
  findings      : [         // embedded subdocument array
    {
      checkName   : String
      passed      : Boolean
      detail      : String
      severity    : String  // None | Low | Medium | High | Critical
      weight      : Number  // penalty value
      owasp       : String  // OWASP API Top 10 (2023) category
      remediation : String  // actionable fix guidance
    }
  ]
  overallScore  : Number    // pre-computed at write time
  severity      : String    // denormalized for fast aggregation
  scanDuration  : Number    // milliseconds
  tokenUsed     : Boolean
  createdAt     : Date      // auto-managed by Mongoose
  updatedAt     : Date
}
```

### Indexes

```javascript
{ target: 1 }                 // history lookup by target URL
{ target: 1, createdAt: -1 } // newest scans per target (compound)
{ severity: 1 }               // severity distribution aggregation
```

### Aggregation Pipelines

**Most Common Failures**

```
$unwind findings           → explode array (1 scan × 9 findings = 9 documents)
→ $match passed: false     → filter to failures only
→ $group by checkName      → count occurrences
→ $sort by failCount DESC
→ $limit 10
```

**Severity Distribution**

```
$group by severity → $avg overallScore → $sort by count
```

**Target History (Trend)**

```
$match target → $sort createdAt ASC → $project score + failed count
```

---

## 🚀 Setup & Installation

### Prerequisites

- Node.js v18+
- MongoDB Atlas account (free tier is sufficient)

### Clone & Install

```bash
git clone https://github.com/yourusername/apifortify.git
cd apifortify
npm install
```

### Environment Configuration

Create a `.env` file in the project root:

```env
PORT=5000
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/apifortify?retryWrites=true&w=majority
```

### Run

```bash
# Development — auto-restart on file changes
npm run dev

# Production
npm start
```

Open `http://localhost:5000`

---

## 🔌 API Reference

### Scan Endpoints

| Method   | Endpoint         | Description                                           |
| -------- | ---------------- | ----------------------------------------------------- |
| `POST`   | `/api/scan`      | Run a new security scan                               |
| `GET`    | `/api/scans`     | List scan history (supports `?target=` and `?limit=`) |
| `GET`    | `/api/scans/:id` | Get full scan result by ID                            |
| `DELETE` | `/api/scans/:id` | Delete a scan record                                  |

### Stats Endpoints

| Method | Endpoint              | Description                                        |
| ------ | --------------------- | -------------------------------------------------- |
| `GET`  | `/api/stats/summary`  | Dashboard summary — totals, averages, recent scans |
| `GET`  | `/api/stats/severity` | Severity distribution aggregation                  |
| `GET`  | `/api/stats/findings` | Most common failed checks                          |
| `GET`  | `/api/stats/history`  | Per-target scan history and trend                  |

### Report Endpoints

| Method | Endpoint              | Description                                 |
| ------ | --------------------- | ------------------------------------------- |
| `GET`  | `/api/report/:id/pdf` | Download professional PDF report for a scan |

### Example Request

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "endpoint": "/users/1",
    "token": "your-bearer-token"
  }'
```

### Example Response

```json
{
  "success": true,
  "data": {
    "_id": "65f1a2b3c4d5e6f7a8b9c0d1",
    "target": "https://api.example.com",
    "endpoint": "/users/1",
    "overallScore": 46,
    "severity": "High Risk",
    "scanDuration": 1053,
    "findings": [
      {
        "checkName": "Security Headers",
        "passed": false,
        "severity": "High",
        "weight": 15,
        "owasp": "API8:2023 - Security Misconfiguration",
        "detail": "Missing security headers: content-security-policy, strict-transport-security",
        "remediation": "Use the helmet npm package: app.use(helmet())"
      }
    ],
    "createdAt": "2026-02-28T06:00:00.000Z"
  }
}
```

---

## 🛠️ Tech Stack

| Layer          | Technology                | Purpose                                 |
| -------------- | ------------------------- | --------------------------------------- |
| Runtime        | Node.js v18+              | Server-side JavaScript                  |
| Web Framework  | Express.js                | REST API and static file serving        |
| Database       | MongoDB Atlas             | Document storage and aggregations       |
| ODM            | Mongoose                  | Schema definition, validation, indexing |
| HTTP Client    | Axios                     | Outbound security check requests        |
| PDF Generation | PDFKit                    | Server-side PDF report generation       |
| Frontend       | HTML5 + CSS3 + Vanilla JS | Dashboard — no frameworks               |

---

## ⚠️ Responsible Use

APIFortify is designed for:

- Security assessment of APIs **you own or have explicit written permission to test**
- Development and staging environment scanning before production deployment
- Security regression testing in CI/CD pipelines
- Learning and demonstrating OWASP API Security concepts

**Do not use against systems you do not own or have written authorization to test. Unauthorized security scanning may be illegal in your jurisdiction.**

---

## 🗺️ Roadmap

- [ ] CI/CD integration — GitHub Actions workflow for automated scanning
- [ ] Scan scheduling — cron-based recurring scans per target
- [ ] Slack / webhook notifications on critical findings
- [ ] Scan comparison — diff two scans for the same target
- [ ] Custom check plugins — extend the scanner with user-defined checks
- [ ] CVSS scoring integration

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  Built with Node.js · MongoDB · PDFKit &nbsp;|&nbsp; OWASP API Security Top 10 (2023)
</div>
