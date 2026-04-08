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
  cwe_id VARCHAR(20) DEFAULT NULL,
  ai_summary TEXT DEFAULT NULL,
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
  type ENUM('scanner','assistant','automation') NOT NULL DEFAULT 'scanner',
  status ENUM('configured','ready','disabled') NOT NULL DEFAULT 'ready',
  endpoint_url VARCHAR(255) DEFAULT NULL,
  description TEXT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_integration_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

ALTER TABLE imports
  ADD COLUMN IF NOT EXISTS source_type ENUM('manual','url','upload') NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS source_detail VARCHAR(255) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS artifact_path VARCHAR(255) DEFAULT NULL;

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

INSERT INTO integrations (project_id, name, type, status, endpoint_url, description)
SELECT p.id, 'MobSF', 'scanner', 'ready', 'http://localhost:8000', 'Mobile application static and dynamic analysis add-on.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'MobSF');

INSERT INTO integrations (project_id, name, type, status, endpoint_url, description)
SELECT p.id, 'OASM Assistant', 'assistant', 'configured', 'https://oasm.example.local', 'Intelligence assistant integration for threat triage and guidance.'
FROM projects p
WHERE NOT EXISTS (SELECT 1 FROM integrations WHERE name = 'OASM Assistant');

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

INSERT INTO findings (scan_run_id, severity, status, cwe_id, ai_summary, ai_confidence, title, category, file_path, line_number, description, recommendation)
SELECT sr.id, 'critical', 'open', 'CWE-78', 'Likely command injection path with direct process execution.', 91, 'Command injection path', 'SAST', 'app/services/parser.php', 131,
       'Untrusted command content is passed into a shell execution path.', 'Replace shell execution with a safe API and strict allow-listing.'
FROM scan_runs sr
WHERE sr.scan_type = 'sast'
LIMIT 1;

INSERT INTO findings (scan_run_id, severity, status, cwe_id, ai_summary, ai_confidence, title, category, file_path, line_number, description, recommendation)
SELECT sr.id, 'high', 'open', 'CWE-352', 'Missing anti-forgery controls on a state-changing form.', 88, 'Missing anti-CSRF token', 'DAST', 'views/profile.php', 42,
       'A state-changing form can be submitted without a CSRF token.', 'Add token generation, validation, and same-site cookie protection.'
FROM scan_runs sr
WHERE sr.scan_type = 'zap'
LIMIT 1;

INSERT INTO findings (scan_run_id, severity, status, cwe_id, ai_summary, ai_confidence, title, category, file_path, line_number, description, recommendation)
SELECT sr.id, 'medium', 'false_positive', 'CWE-200', 'External package risk appears informational and should be manually confirmed.', 74, 'Outdated dependency', 'SCA', 'composer.lock', NULL,
       'A third-party package includes a known medium-risk vulnerability.', 'Upgrade to a patched version and re-run dependency analysis.'
FROM scan_runs sr
WHERE sr.scan_type = 'sca'
LIMIT 1;
