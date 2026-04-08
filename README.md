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
- Role-based access for admin, manager, analyst, and client users
- Client onboarding for logos, URLs, and source credentials
- Source import by JSON, URL, or uploaded archive
- Client-ready report downloads for PDF-ready print, Word, Excel, CSV, and JSON
- Add-on management for MobSF and OASM Assistant integrations

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

Other demo users:

- `manager@cyber-security.local`
- `analyst@cyber-security.local`
- `client@cyber-security.local`

Add-ons:

- MobSF runs as a local Docker service on port `8000`
- OASM Assistant is tracked as an external assistant endpoint for attack-surface triage

Useful screens:

- `home.php` dashboard
- `clients.php` client onboarding
- `addons.php` add-ons management

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
