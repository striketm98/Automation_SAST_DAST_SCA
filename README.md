# cyber-Security

Client-facing PHP dashboard for consolidating:

- SAST results
- DAST results
- SonarQube quality metrics
- OWASP ZAP findings
- Dependency-check / SCA results

## What this repo provides

- Modern PHP UI with HTML, CSS, and JavaScript
- MySQL-backed storage for projects, scans, and findings
- A unified report page with summary cards, risk breakdowns, and export options
- Docker Compose stack for the app, MySQL, SonarQube, ZAP, and Dependency-Check
- Login-gated access with a demo admin account

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
