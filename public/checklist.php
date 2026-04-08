<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();
$message = null;
$error = null;
$issues = [];

$project = null;
if ($pdo) {
    try {
        $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
        $pdo->exec("
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
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    } catch (Throwable $e) {
        $project = null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$pdo) {
        $error = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $error = 'Your session expired. Please try again.';
    } else {
        $vulnerabilityType = trim((string) ($_POST['vulnerability_type'] ?? ''));
        $issueTitle = trim((string) ($_POST['issue_title'] ?? ''));
        $issueDescription = trim((string) ($_POST['issue_description'] ?? ''));
        $pocNotes = trim((string) ($_POST['poc_notes'] ?? ''));
        $severity = strtolower(trim((string) ($_POST['severity'] ?? 'medium')));
        $status = strtolower(trim((string) ($_POST['status'] ?? 'open')));
        $createdBy = (string) ((currentUser()['display_name'] ?? currentUser()['email'] ?? 'analyst'));
        $projectId = !empty($project['id']) ? (int) $project['id'] : null;

        if ($vulnerabilityType === '' || $issueTitle === '' || $issueDescription === '') {
            $error = 'Please provide vulnerability type, issue title, and issue description.';
        } elseif (!in_array($severity, ['critical', 'high', 'medium', 'low', 'info'], true)) {
            $error = 'Invalid severity selected.';
        } elseif (!in_array($status, ['open', 'validated', 'false_positive', 'resolved'], true)) {
            $error = 'Invalid status selected.';
        } else {
            try {
                $stmt = $pdo->prepare('
                    INSERT INTO pentest_checklist_issues
                    (project_id, vulnerability_type, issue_title, issue_description, poc_notes, severity, status, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ');
                $stmt->execute([
                    $projectId,
                    $vulnerabilityType,
                    $issueTitle,
                    $issueDescription,
                    $pocNotes !== '' ? $pocNotes : null,
                    $severity,
                    $status,
                    $createdBy,
                ]);
                $message = 'Checklist issue added successfully.';
            } catch (Throwable $e) {
                $error = 'Unable to save checklist issue right now.';
            }
        }
    }
}

if ($pdo) {
    try {
        if (!empty($project['id'])) {
            $listStmt = $pdo->prepare('SELECT * FROM pentest_checklist_issues WHERE project_id = ? ORDER BY created_at DESC');
            $listStmt->execute([(int) $project['id']]);
            $issues = $listStmt->fetchAll();
        } else {
            $issues = $pdo->query('SELECT * FROM pentest_checklist_issues ORDER BY created_at DESC LIMIT 100')->fetchAll();
        }
    } catch (Throwable $e) {
        $issues = [];
    }
}

$issues = $issues ?: [
    [
        'vulnerability_type' => 'Web - Injection',
        'issue_title' => 'Input validation missing on search endpoint',
        'issue_description' => 'Search endpoint accepts unsafe input patterns and needs strict server-side validation.',
        'poc_notes' => 'Validation evidence only: captured request/response and confirmed fix in retest build.',
        'severity' => 'high',
        'status' => 'open',
        'created_by' => 'Security Analyst',
        'created_at' => date('Y-m-d H:i:s'),
    ],
];

$tabs = [
    ['label' => 'Pentest checklist', 'href' => 'checklist.php', 'active' => true],
    ['label' => 'Open ASM', 'href' => 'oasm.php', 'active' => false],
];
$dashboard = sampleDashboard();
$projectInfo = $project ?: $dashboard['project'];
$user = currentUser();
$role = currentUserRole();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Pentest Checklist</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body class="checklist-page">
  <div class="app-shell checklist-shell">
    <aside class="sidebar">
      <div class="brand-lockup sidebar-brand">
        <img src="<?= e((string) ($projectInfo['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">cyber-Security</p>
          <strong>Checklist console</strong>
        </div>
      </div>
      <nav class="side-nav">
        <a class="side-link" href="home.php">Dashboard</a>
        <a class="side-link" href="audit.php">Audit</a>
        <a class="side-link active" href="checklist.php">Checklist</a>
        <a class="side-link" href="oasm.php">Open ASM</a>
        <a class="side-link" href="report.php">Report</a>
        <a class="side-link" href="deliverables.php">Deliverables</a>
      </nav>
      <div class="sidebar-card">
        <span class="tag tag-okay">Live workflow</span>
        <h3><?= e((string) ($projectInfo['name'] ?? 'Security Program')) ?></h3>
        <p><?= e((string) ($projectInfo['client_name'] ?? 'Client')) ?></p>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar pro-topbar">
        <div class="search-pill">
          <span class="search-icon" aria-hidden="true"></span>
          <input type="text" placeholder="Search checklist items, vulnerabilities, and notes" aria-label="Search checklist">
        </div>
        <div class="topbar-actions">
          <span class="status-chip"><?= e(ucfirst($role)) ?></span>
          <a class="button ghost" href="audit.php">Audit</a>
          <a class="button" href="oasm.php">Open ASM</a>
          <span class="user-badge"><?= e(strtoupper(substr((string) ($user['display_name'] ?? 'A'), 0, 2))) ?></span>
        </div>
      </header>

      <section class="hero-strip checklist-hero">
        <div>
          <p class="eyebrow">Pentest checklist</p>
          <h1>Authorized validation checklist</h1>
          <p class="subhead">Track vulnerability coverage, issue descriptions, and safe PoC evidence notes in a professional client-facing workflow.</p>
        </div>
        <div class="hero-actions">
          <?php foreach ($tabs as $tab): ?>
            <a class="button <?= $tab['active'] ? '' : 'ghost' ?>" href="<?= e($tab['href']) ?>"><?= e($tab['label']) ?></a>
          <?php endforeach; ?>
        </div>
      </section>

      <section class="panel wide">
      <div class="panel-header">
        <h3>Checklist coverage</h3>
        <span class="muted">Review each area before marking a finding as validated or false positive</span>
      </div>
      <div class="checklist-grid">
        <?php foreach (pentestChecklist() as $group): ?>
          <article class="checklist-card">
            <h4><?= e((string) $group['section']) ?></h4>
            <ul class="checklist-list">
              <?php foreach ($group['items'] as $item): ?>
                <li><span class="check-dot"></span><span><?= e((string) $item) ?></span></li>
              <?php endforeach; ?>
            </ul>
          </article>
        <?php endforeach; ?>
      </div>
      </section>

      <section class="panel wide">
      <div class="panel-header">
        <h3>Add new checklist issue</h3>
        <span class="muted">Track vulnerability type, issue description, and safe PoC evidence notes</span>
      </div>
      <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
      <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>
      <form method="post" class="import-form">
        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
        <label>
          <span>Vulnerability type</span>
          <select name="vulnerability_type" required>
            <option value="">Select type</option>
            <option value="Web - Injection">Web - Injection</option>
            <option value="Web - XSS">Web - XSS</option>
            <option value="Web - Access Control">Web - Access Control</option>
            <option value="API - Authentication">API - Authentication</option>
            <option value="API - Data Exposure">API - Data Exposure</option>
            <option value="Mobile - Static">Mobile - Static</option>
            <option value="Mobile - Dynamic">Mobile - Dynamic</option>
            <option value="SAST - Code Risk">SAST - Code Risk</option>
            <option value="SCA - Dependency Risk">SCA - Dependency Risk</option>
            <option value="OASM - Exposure">OASM - Exposure</option>
            <option value="PT - Validation Finding">PT - Validation Finding</option>
          </select>
        </label>
        <label>
          <span>Severity</span>
          <select name="severity" required>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium" selected>Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <select name="status" required>
            <option value="open" selected>Open</option>
            <option value="validated">Validated</option>
            <option value="false_positive">False positive</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
        <label class="full">
          <span>Issue title</span>
          <input type="text" name="issue_title" placeholder="Short issue title" required>
        </label>
        <label class="full">
          <span>Issue description</span>
          <textarea name="issue_description" rows="4" placeholder="Describe the issue and impacted component" required></textarea>
        </label>
        <label class="full">
          <span>PoC / validation notes (safe)</span>
          <textarea name="poc_notes" rows="4" placeholder="Store safe evidence only (request IDs, screenshots, logs, retest notes). Avoid exploit payloads."></textarea>
        </label>
        <div class="form-actions full">
          <button class="button" type="submit">Add issue</button>
        </div>
      </form>
      </section>

      <section class="panel wide">
      <div class="panel-header">
        <h3>Checklist issue register</h3>
        <span class="muted">Custom issues added by analysts</span>
      </div>
      <div class="finding-list">
        <?php foreach ($issues as $item): ?>
          <article class="finding-card <?= e(severityClass((string) ($item['severity'] ?? 'info'))) ?>">
            <div class="finding-head">
              <strong><?= e((string) ($item['issue_title'] ?? 'Checklist issue')) ?></strong>
              <div class="finding-badges">
                <span class="tag"><?= e(strtoupper((string) ($item['severity'] ?? 'info'))) ?></span>
                <span class="tag"><?= e(strtoupper(str_replace('_', ' ', (string) ($item['status'] ?? 'open')))) ?></span>
                <span class="tag"><?= e((string) ($item['vulnerability_type'] ?? 'General')) ?></span>
              </div>
            </div>
            <p><?= e((string) ($item['issue_description'] ?? '')) ?></p>
            <p class="recommendation"><strong>PoC / Validation notes:</strong> <?= e((string) ($item['poc_notes'] ?? 'No safe PoC notes added yet.')) ?></p>
            <div class="finding-foot">
              <span><?= e((string) ($item['created_by'] ?? 'analyst')) ?></span>
              <span><?= e((string) ($item['created_at'] ?? '')) ?></span>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Safe evidence guidance</h3>
        <span class="muted">Record outcome, not exploit steps</span>
      </div>
      <div class="access-grid">
        <div><span>Store</span><strong>Screenshots, headers, log excerpts, and retest results</strong></div>
        <div><span>Avoid</span><strong>Exploit payloads, weaponized PoC steps, or destructive actions</strong></div>
        <div><span>Map</span><strong>CWE, severity, and remediation owner</strong></div>
        <div><span>Close</span><strong>Only after validation on a patched build</strong></div>
      </div>
      </section>
    </main>
  </div>
</body>
</html>
