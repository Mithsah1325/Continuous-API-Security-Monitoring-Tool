# 🛡️ APIScan: Enterprise-Grade REST API Security Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![OWASP API Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010-blue)](https://owasp.org/www-project-api-security/)

**APIScan** is a high-performance, automated security scanning engine designed to identify vulnerabilities in RESTful architectures. Built with a focus on the **OWASP API Security Top 10 (2023)**, it provides developers with real-time posture analysis, weighted risk scoring, and actionable remediation intelligence.

[🚀 Get Started](#-setup--installation) | [📊 Features](#-features) | [🔌 API Docs](#-api-reference) | [🎥 Demo](#-dashboard-preview)

---

## 🖥️ Dashboard Preview
Real-time dashboard with scan history, severity distribution, and OWASP-mapped findings.
![APIScan Dashboard](https://github.com/Mithsah1325/Continuous-API-Security-Monitoring-Tool/raw/main/api%20security%20platform.png)

[![APIScan Demo Video](https://img.youtube.com/vi/_UmvuNB7ISY/0.jpg)](https://youtu.be/_UmvuNB7ISY?si=j83c5q1WJrZycRdg)
---

## ✨ Key Features

* **Parallel Security Engine:** Executes 9 distinct security modules simultaneously using Node.js asynchronous non-blocking I/O.
* **Intelligent Risk Scoring:** Implements a proprietary weighted algorithm (0-100) to classify security posture from *Secure* to *Critical*.
* **Automated Remediation:** Provides specific, developer-centric fix guidance (e.g., `helmet` integration, CORS hardening) for every finding.
* **Enterprise Reporting:** Generates comprehensive PDF reports via **PDFKit**, suitable for stakeholders and CI/CD audit trails.
* **Advanced Data Aggregation:** Leverages **MongoDB Aggregation Pipelines** for trend analysis, severity distribution, and "Most Common Failure" tracking.

---

## 🛠️ Technical Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Node.js (v18+), Express.js | Core logic and RESTful routing |
| **Database** | MongoDB Atlas | Scalable document storage for scan results |
| **ODM** | Mongoose | Schema validation and compound indexing |
| **Security** | OWASP-mapped logic, Axios | Request injection and header analysis |
| **Reporting** | PDFKit | Automated server-side PDF generation |
| **Frontend** | Vanilla JS, HTML5, CSS3 | Responsive dashboard without framework overhead |

---

## 📐 Architecture & Design Decisions

### Why MongoDB (Document Model)?
I opted for a **Document Model** over Relational (SQL) to optimize for scan performance:
* **Eliminating Joins:** A single scan result, containing 9+ nested findings, is stored as one document. This avoids the overhead of multi-table joins during retrieval.
* **Optimized Indexing:** Implemented compound indexes on `{ target: 1, createdAt: -1 }` to allow for sub-second retrieval of historical trend data.

### Security Coverage (OWASP 2023):
The scanner includes modules for:
1. **Broken Object Level Authorization (BOLA)** - ID Enumeration checks.
2. **Broken Authentication** - Verification of sensitive endpoint protection.
3. **Security Misconfigurations** - Header, CORS, and Verbose Error handling.
4. **Unrestricted Resource Consumption** - Rate limiting detection.

---

## 🚀 Setup & Installation

### 1. Clone & Dependencies
```bash
git clone [https://github.com/Mithsah1325/Continuous-API-Security-Monitoring-Tool.git](https://github.com/Mithsah1325/Continuous-API-Security-Monitoring-Tool.git)
cd Continuous-API-Security-Monitoring-Tool
npm install
