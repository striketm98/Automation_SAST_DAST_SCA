# 🛡️ Cyber-Security Dashboard

> **Enterprise-Grade Security Audit & Compliance Reporting Platform**

---

## Overview

Professional client-facing PHP dashboard for consolidating:

- ✅ **SAST** - Static Application Security Testing results
- ✅ **DAST** - Dynamic Application Security Testing results
- ✅ **SonarQube** - Quality metrics & code analysis
- ✅ **OWASP ZAP** - Web application security findings
- ✅ **Dependency-Check / SCA** - Software composition analysis

---

## 📦 What This Platform Provides

- 🎨 **Modern Responsive UI** - Professional PHP dashboard with HTML5, CSS3, and JavaScript
- 💾 **Secure Data Storage** - MySQL-backed database for projects, scans, and findings
- 📊 **Unified Reporting** - Comprehensive dashboard with summary cards, risk breakdowns, and export options
- 🐳 **Docker Stack** - Complete containerized environment: App, MySQL, SonarQube, ZAP, and Dependency-Check
- 🔐 **Enterprise Security** - Role-based access control with secure authentication

## Run it

```bash
docker compose up --build
```

Open:

- App: http://localhost:8080
- SonarQube: http://localhost:9000

Login:

- Email: `admin@cyber-security.local`
- Password: `ChangeMe123!`

## Importing results

The dashboard supports JSON uploads for scan results. You can map output from:

- SonarQube API
- OWASP ZAP reports
- Dependency-Check reports
- Internal SAST tools

The current app stores normalized findings in MySQL so a single client-ready report can combine all sources.

## Notes

- This first pass uses a clean single-brand UI and seeded demo data when the database is empty.
- SonarQube and ZAP are run as companion services in the same Compose stack. That is the practical way to keep the solution maintainable; they are not forced into one process.
