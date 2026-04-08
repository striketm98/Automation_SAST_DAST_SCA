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
- Add-on management for MobSF, OASM Assistant, and Python pentest integrations
- Tool inventory for scanners, mobile security, pentest, and assistant services
- Pentest checklist tab and Open Attack Surface Management view
- Client deliverables page for a printable bundle of findings, checklist, and OASM inventory
- Audit console with SAST, DAST, SCA, Mobile, PT, and OASM filters

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
- Password for all demo users: `ChangeMe123!`

Add-ons:

- MobSF runs as a local Docker service on port `8000`
- MobSF runs as root in the container so it can initialize its `.MobSF` config volume cleanly
- OASM Assistant is tracked as an external assistant endpoint for attack-surface triage
- sqlmap is packaged as an optional Python container for authorized testing workflows
- Python Pentest Suite is packaged as a Python API for safe validation notes, evidence capture, and remediation planning
- Open Attack Surface Management is packaged as a Python API for asset exposure tracking and scope control
- OASM supports GUI edits, bulk JSON import, and an audit trail for asset changes

Tool management:

- Open `addons.php` to register new tools
- Upload a tool logo so it shows in the dashboard and report
- Choose the connection type: Docker, API, Python, or manual

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
