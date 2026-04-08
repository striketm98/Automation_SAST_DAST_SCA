CREATE DATABASE IF NOT EXISTS security_dashboard;
USE security_dashboard;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(160) NOT NULL UNIQUE,
  display_name VARCHAR(160) NOT NULL,
  password_sha256 CHAR(64) NOT NULL,
  role ENUM('admin','manager','analyst','client') NOT NULL DEFAULT 'admin',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE users
  MODIFY role ENUM('admin','manager','analyst','client') NOT NULL DEFAULT 'admin';

CREATE TABLE IF NOT EXISTS projects (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  client_name VARCHAR(160) NOT NULL,
  client_logo_path VARCHAR(255) DEFAULT NULL,
  portal_url VARCHAR(255) DEFAULT NULL,
  repository_url VARCHAR(255) DEFAULT NULL,
  target_url VARCHAR(255) DEFAULT NULL,
  source_url VARCHAR(255) DEFAULT NULL,
  source_username VARCHAR(160) DEFAULT NULL,
  source_password_hint VARCHAR(255) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS client_logo_path VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS portal_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS source_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS source_username VARCHAR(160) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS source_password_hint VARCHAR(255) DEFAULT NULL;

CREATE TABLE IF NOT EXISTS scan_runs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  scan_type ENUM('sast','dast','sca','sonarqube','zap') NOT NULL,
  tool_name VARCHAR(80) NOT NULL,
  status ENUM('queued','running','completed','failed') NOT NULL DEFAULT 'completed',
  started_at DATETIME NULL,
  completed_at DATETIME NULL,
  summary TEXT NULL,
  raw_payload JSON NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_scan_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  scan_run_id INT NOT NULL,
  severity ENUM('critical','high','medium','low','info') NOT NULL,
  status ENUM('open','false_positive','accepted_risk','resolved') NOT NULL DEFAULT 'open',
  claim_state ENUM('unclaimed','claimed') NOT NULL DEFAULT 'unclaimed',
  claimed_by VARCHAR(160) DEFAULT NULL,
  claimed_at DATETIME DEFAULT NULL,
  cwe_id VARCHAR(20) DEFAULT NULL,
  ai_issue_summary TEXT DEFAULT NULL,
  ai_summary TEXT DEFAULT NULL,
  ai_remediation TEXT DEFAULT NULL,
  validation_notes TEXT DEFAULT NULL,
  ai_confidence TINYINT UNSIGNED DEFAULT NULL,
  title VARCHAR(220) NOT NULL,
  category VARCHAR(120) NOT NULL,
  file_path VARCHAR(255) DEFAULT NULL,
  line_number INT DEFAULT NULL,
  description TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  analyst_comment TEXT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_finding_scan FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS imports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  source_type ENUM('manual','url','upload') NOT NULL DEFAULT 'manual',
  source_name VARCHAR(80) NOT NULL,
  source_detail VARCHAR(255) DEFAULT NULL,
  artifact_path VARCHAR(255) DEFAULT NULL,
  file_name VARCHAR(255) NOT NULL,
  imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_import_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS integrations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  name VARCHAR(120) NOT NULL,
  vendor_name VARCHAR(120) DEFAULT NULL,
  integration_profile VARCHAR(80) DEFAULT NULL,
  type ENUM('scanner','assistant','automation') NOT NULL DEFAULT 'scanner',
  tool_category ENUM('sast','dast','sca','mobile','pentest','assistant','automation') NOT NULL DEFAULT 'automation',
  connection_type ENUM('docker','api','python','manual') NOT NULL DEFAULT 'manual',
  status ENUM('configured','ready','disabled') NOT NULL DEFAULT 'ready',
  endpoint_url VARCHAR(255) DEFAULT NULL,
  api_base_url VARCHAR(255) DEFAULT NULL,
  scan_submit_url VARCHAR(255) DEFAULT NULL,
  result_url VARCHAR(255) DEFAULT NULL,
  auth_type VARCHAR(40) DEFAULT NULL,
  documentation_url VARCHAR(255) DEFAULT NULL,
  last_tested_at DATETIME DEFAULT NULL,
  last_test_status ENUM('unknown','up','down','partial') NOT NULL DEFAULT 'unknown',
  last_test_detail VARCHAR(255) DEFAULT NULL,
  tool_logo_path VARCHAR(255) DEFAULT NULL,
  description TEXT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_integration_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_surface_assets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  asset_type ENUM('domain','subdomain','ip','url','api','mobile','repo') NOT NULL DEFAULT 'url',
  asset_name VARCHAR(160) NOT NULL,
  asset_url VARCHAR(255) DEFAULT NULL,
  exposure ENUM('public','internal','restricted') NOT NULL DEFAULT 'public',
  status ENUM('discovered','reviewed','in_scope','out_of_scope') NOT NULL DEFAULT 'discovered',
  notes TEXT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_asset_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_surface_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  asset_id INT DEFAULT NULL,
  action ENUM('created','updated','deleted','imported') NOT NULL,
  actor VARCHAR(160) NOT NULL,
  details TEXT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_history_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  CONSTRAINT fk_history_asset FOREIGN KEY (asset_id) REFERENCES attack_surface_assets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS pentest_checklist_issues (
  id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT DEFAULT NULL,
  vulnerability_type VARCHAR(80) NOT NULL,
  issue_title VARCHAR(180) NOT NULL,
  issue_description TEXT NOT NULL,
  poc_notes TEXT DEFAULT NULL,
  severity ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
  status ENUM('open','validated','false_positive','resolved') NOT NULL DEFAULT 'open',
  created_by VARCHAR(160) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_checklist_project (project_id)
);

ALTER TABLE integrations
  ADD COLUMN IF NOT EXISTS vendor_name VARCHAR(120) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS integration_profile VARCHAR(80) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS tool_category ENUM('sast','dast','sca','mobile','pentest','assistant','automation') NOT NULL DEFAULT 'automation',
  ADD COLUMN IF NOT EXISTS connection_type ENUM('docker','api','python','manual') NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS endpoint_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS api_base_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS scan_submit_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS result_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS auth_type VARCHAR(40) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS documentation_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS last_tested_at DATETIME DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS last_test_status ENUM('unknown','up','down','partial') NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS last_test_detail VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS tool_logo_path VARCHAR(255) DEFAULT NULL;

ALTER TABLE imports
  ADD COLUMN IF NOT EXISTS source_type ENUM('manual','url','upload') NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS source_detail VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS artifact_path VARCHAR(255) DEFAULT NULL;

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS claim_state ENUM('unclaimed','claimed') NOT NULL DEFAULT 'unclaimed',
  ADD COLUMN IF NOT EXISTS claimed_by VARCHAR(160) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS claimed_at DATETIME DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS ai_issue_summary TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS ai_remediation TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS validation_notes TEXT DEFAULT NULL;

ALTER TABLE attack_surface_assets
  ADD COLUMN IF NOT EXISTS asset_type ENUM('domain','subdomain','ip','url','api','mobile','repo') NOT NULL DEFAULT 'url',
  ADD COLUMN IF NOT EXISTS asset_url VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS exposure ENUM('public','internal','restricted') NOT NULL DEFAULT 'public',
  ADD COLUMN IF NOT EXISTS status ENUM('discovered','reviewed','in_scope','out_of_scope') NOT NULL DEFAULT 'discovered',
  ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT NULL;

ALTER TABLE attack_surface_history
  ADD COLUMN IF NOT EXISTS asset_id INT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS action ENUM('created','updated','deleted','imported') NOT NULL,
  ADD COLUMN IF NOT EXISTS actor VARCHAR(160) NOT NULL,
  ADD COLUMN IF NOT EXISTS details TEXT DEFAULT NULL;

INSERT INTO users (email, display_name, password_sha256, role)
SELECT 'admin@cyber-security.local', 'Security Admin', SHA2('ChangeMe123!', 256), 'admin'
WHERE NOT EXISTS (SELECT 1 FROM users);

INSERT INTO users (email, display_name, password_sha256, role)
SELECT 'manager@cyber-security.local', 'Security Manager', SHA2('ChangeMe123!', 256), 'manager'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'manager');

INSERT INTO users (email, display_name, password_sha256, role)
SELECT 'analyst@cyber-security.local', 'Security Analyst', SHA2('ChangeMe123!', 256), 'analyst'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'analyst');

INSERT INTO users (email, display_name, password_sha256, role)
SELECT 'client@cyber-security.local', 'Client Viewer', SHA2('ChangeMe123!', 256), 'client'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'client');

INSERT INTO projects (name, client_name, repository_url, target_url)
SELECT 'Client Portal', 'Acme Corporation', 'https://example.com/repo', 'https://example.com/app'
WHERE NOT EXISTS (SELECT 1 FROM projects);

UPDATE projects
SET client_logo_path = COALESCE(client_logo_path, 'assets/img/cyber-logo.png'),
    portal_url = COALESCE(portal_url, 'https://example.com/app'),
    source_url = COALESCE(source_url, 'https://example.com/repo'),
    source_username = COALESCE(source_username, 'devops@example.com'),
    source_password_hint = COALESCE(source_password_hint, 'Provided separately to the delivery team')
WHERE client_logo_path IS NULL OR portal_url IS NULL OR source_url IS NULL;

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'MobSF', 'MobSF', 'mobsf', 'scanner', 'mobile', 'docker', 'ready', 'http://localhost:8000', 'http://localhost:8000', 'http://localhost:8000/api/v1/scan', 'http://localhost:8000/api/v1/report', 'token', 'https://github.com/MobSF/docs', 'Mobile application static and dynamic analysis add-on.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'MobSF');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'OASM Assistant', 'cyber-Security', 'oasm-assistant', 'assistant', 'assistant', 'api', 'configured', 'https://oasm.example.local', 'https://oasm.example.local', '/api/summary', '/api/assets', 'bearer', NULL, 'Intelligence assistant integration for threat triage and guidance.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'OASM Assistant');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'OWASP ZAP', 'OWASP', 'zap', 'scanner', 'dast', 'docker', 'ready', 'http://localhost:8090', 'http://localhost:8090', '/JSON/spider/action/scan/', '/JSON/core/view/alerts/', 'none', 'https://www.zaproxy.org/docs/', 'Dynamic application security testing engine for baseline and authenticated scans.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'OWASP ZAP');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'SonarQube', 'SonarSource', 'sonarqube', 'scanner', 'sast', 'docker', 'ready', 'http://localhost:9000', 'http://localhost:9000', '/api/issues/search', '/api/measures/component', 'token', 'https://docs.sonarsource.com/', 'Source-code quality and static analysis platform.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'SonarQube');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'Dependency-Check', 'OWASP', 'dependency-check', 'scanner', 'sca', 'docker', 'ready', 'http://localhost:3300', 'http://localhost:3300', '/api/report', '/api/report', 'none', 'https://jeremylong.github.io/DependencyCheck/', 'Open-source dependency and vulnerability analysis.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'Dependency-Check');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'sqlmap', 'sqlmap', 'sqlmap', 'scanner', 'pentest', 'python', 'configured', 'http://localhost:6000', 'http://localhost:6000', '/run', '/results', 'token', 'https://sqlmap.org/', 'Authorized SQL injection testing container for controlled assessments.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'sqlmap');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'Python Pentest Suite', 'cyber-Security', 'python-pentest-suite', 'automation', 'pentest', 'python', 'ready', 'http://pentest-python:6100', 'http://pentest-python:6100', '/catalog', '/summary', 'none', NULL, 'Python-based authorized validation companion for safe checks, evidence notes, and remediation planning.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'Python Pentest Suite');

INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, description)
SELECT p.id, 'Open Attack Surface Management', 'cyber-Security', 'oasm', 'assistant', 'assistant', 'api', 'ready', 'http://oasm:6200', 'http://oasm:6200', '/assets', '/summary', 'none', NULL, 'Attack-surface inventory and exposure tracking module for approved assets.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'Open Attack Surface Management');

INSERT INTO scan_runs (project_id, scan_type, tool_name, status, started_at, completed_at, summary, raw_payload)
SELECT p.id, 'sonarqube', 'SonarQube', 'completed', NOW() - INTERVAL 3 DAY, NOW() - INTERVAL 3 DAY + INTERVAL 12 MINUTE,
       'Code quality profile uploaded from SonarQube.', JSON_OBJECT('bugs', 3, 'vulnerabilities', 2, 'code_smells', 17, 'coverage', 78)
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM scan_runs);

INSERT INTO scan_runs (project_id, scan_type, tool_name, status, started_at, completed_at, summary, raw_payload)
SELECT p.id, 'zap', 'OWASP ZAP', 'completed', NOW() - INTERVAL 2 DAY, NOW() - INTERVAL 2 DAY + INTERVAL 19 MINUTE,
       'DAST baseline run completed.', JSON_OBJECT('alerts', 6, 'high', 1, 'medium', 2, 'low', 3)
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM scan_runs WHERE scan_type = 'zap');

INSERT INTO scan_runs (project_id, scan_type, tool_name, status, started_at, completed_at, summary, raw_payload)
SELECT p.id, 'sca', 'Dependency-Check', 'completed', NOW() - INTERVAL 1 DAY, NOW() - INTERVAL 1 DAY + INTERVAL 8 MINUTE,
       'Open-source dependency review completed.', JSON_OBJECT('critical', 1, 'high', 4, 'medium', 5, 'licenses', 'MIT, Apache-2.0')
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM scan_runs WHERE scan_type = 'sca');

INSERT INTO scan_runs (project_id, scan_type, tool_name, status, started_at, completed_at, summary, raw_payload)
SELECT p.id, 'sast', 'Internal SAST', 'completed', NOW() - INTERVAL 4 DAY, NOW() - INTERVAL 4 DAY + INTERVAL 22 MINUTE,
       'Static analysis completed against the latest branch.', JSON_OBJECT('issues', 9, 'security_hotspots', 2, 'quality_gate', 'warn')
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM scan_runs WHERE scan_type = 'sast');

INSERT INTO findings (scan_run_id, severity, status, claim_state, claimed_by, claimed_at, cwe_id, ai_summary, ai_confidence, title, category, file_path, line_number, description, recommendation)
SELECT sr.id, 'critical', 'open', 'unclaimed', NULL, NULL, 'CWE-78', 'Likely command injection path with direct process execution.', 91, 'Command injection path', 'SAST', 'app/services/parser.php', 131,
       'Untrusted command content is passed into a shell execution path.', 'Replace shell execution with a safe API and strict allow-listing.'
FROM scan_runs sr
WHERE sr.scan_type = 'sast'
LIMIT 1;

INSERT INTO findings (scan_run_id, severity, status, claim_state, claimed_by, claimed_at, cwe_id, ai_summary, ai_confidence, title, category, file_path, line_number, description, recommendation)
SELECT sr.id, 'high', 'open', 'unclaimed', NULL, NULL, 'CWE-352', 'Missing anti-forgery controls on a state-changing form.', 88, 'Missing anti-CSRF token', 'DAST', 'views/profile.php', 42,
       'A state-changing form can be submitted without a CSRF token.', 'Add token generation, validation, and same-site cookie protection.'
FROM scan_runs sr
WHERE sr.scan_type = 'zap'
LIMIT 1;

INSERT INTO findings (scan_run_id, severity, status, claim_state, claimed_by, claimed_at, cwe_id, ai_summary, ai_confidence, title, category, file_path, line_number, description, recommendation)
SELECT sr.id, 'medium', 'false_positive', 'unclaimed', NULL, NULL, 'CWE-200', 'External package risk appears informational and should be manually confirmed.', 74, 'Outdated dependency', 'SCA', 'composer.lock', NULL,
       'A third-party package includes a known medium-risk vulnerability.', 'Upgrade to a patched version and re-run dependency analysis.'
FROM scan_runs sr
WHERE sr.scan_type = 'sca'
LIMIT 1;

INSERT INTO attack_surface_assets (project_id, asset_type, asset_name, asset_url, exposure, status, notes)
SELECT p.id, 'domain', 'client.example.com', 'https://client.example.com', 'public', 'reviewed', 'Primary internet-facing portal monitored by OASM.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM attack_surface_assets);

INSERT INTO attack_surface_assets (project_id, asset_type, asset_name, asset_url, exposure, status, notes)
SELECT p.id, 'api', 'api.client.example.com', 'https://api.client.example.com', 'public', 'discovered', 'API surface registered for validation and exposure tracking.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM attack_surface_assets WHERE asset_name = 'api.client.example.com');

INSERT INTO attack_surface_history (project_id, asset_id, action, actor, details)
SELECT p.id, NULL, 'imported', 'system', 'Seeded initial attack surface inventory.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM attack_surface_history);

UPDATE findings
SET ai_issue_summary = COALESCE(ai_issue_summary, ai_summary),
    ai_remediation = COALESCE(ai_remediation, recommendation),
    validation_notes = COALESCE(validation_notes, 'Safe validation evidence only. No exploit steps are stored in the platform.')
WHERE ai_issue_summary IS NULL OR ai_remediation IS NULL OR validation_notes IS NULL;
