<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

header('Location: home.php');
exit;

$pdo = Database::pdo();

if ($pdo) {
    $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    if ($project) {
        $scanStmt = $pdo->prepare('SELECT * FROM scan_runs WHERE project_id = ? ORDER BY created_at DESC');
        $scanStmt->execute([$project['id']]);
        $scanRuns = $scanStmt->fetchAll();

        $findingStmt = $pdo->prepare('SELECT f.* FROM findings f INNER JOIN scan_runs s ON s.id = f.scan_run_id WHERE s.project_id = ? ORDER BY FIELD(f.severity, "critical","high","medium","low","info"), f.created_at DESC');
        $findingStmt->execute([$project['id']]);
        $findings = $findingStmt->fetchAll();
    } else {
        $dashboard = sampleDashboard();
        $project = $dashboard['project'];
        $scanRuns = $dashboard['scan_runs'];
        $findings = $dashboard['findings'];
    }

    $summary = [
        'open_findings' => count($findings),
        'critical' => count(array_filter($findings, fn($f) => $f['severity'] === 'critical')),
        'high' => count(array_filter($findings, fn($f) => $f['severity'] === 'high')),
        'medium' => count(array_filter($findings, fn($f) => $f['severity'] === 'medium')),
        'low' => count(array_filter($findings, fn($f) => $f['severity'] === 'low')),
        'coverage' => 78,
        'quality_gate' => 'Ready for review',
    ];
} else {
    $dashboard = sampleDashboard();
    $project = $dashboard['project'];
    $scanRuns = $dashboard['scan_runs'];
    $findings = $dashboard['findings'];
    $summary = $dashboard['metrics'];
}

$recentStatus = $scanRuns[0]['status'] ?? 'queued';
$appName = appName();
$user = currentUser();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e($appName) ?></title>
  <link rel="icon" href="assets/img/favicon.ico">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand-lockup sidebar-brand">
        <img src="assets/img/cyber-logo.png" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">cyber-Security</p>
          <strong>Intelligence Console</strong>
        </div>
      </div>
      <nav class="side-nav">
        <a class="side-link active" href="index.php">Dashboard</a>
        <a class="side-link" href="scan_jobs.php">Scan jobs</a>
        <a class="side-link" href="report.php">Executive report</a>
        <a class="side-link" href="import.php">Import results</a>
      </nav>
      <div class="sidebar-card">
        <span class="tag tag-okay">Live</span>
        <h3><?= e($project['name'] ?? 'Security Program') ?></h3>
        <p><?= e($project['client_name'] ?? 'Client') ?></p>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar pro-topbar">
        <div class="search-pill">
          <span class="search-icon">⌕</span>
          <input type="text" placeholder="Search findings, scans, or projects" aria-label="Search">
        </div>
        <div class="topbar-actions">
          <span class="status-chip">23 October, Friday</span>
          <span class="status-chip">cyber-Security</span>
          <a class="button ghost" href="logout.php">Logout</a>
          <span class="user-badge"><?= e(strtoupper(substr((string) ($user['display_name'] ?? 'A'), 0, 2))) ?></span>
        </div>
      </header>

      <section class="hero-strip">
        <div>
          <p class="eyebrow">Executive security visibility</p>
          <h1><?= e($project['name'] ?? 'Security Program') ?></h1>
          <p class="subhead">A premium reporting workspace for application security, code quality, and dependency risk, built for fast decisions and clear client communication.</p>
        </div>
        <div class="hero-actions">
          <a class="button ghost" href="report.php">View report</a>
          <a class="button" href="import.php">Import findings</a>
        </div>
      </section>

      <section class="dashboard-grid premium-grid">
        <article class="panel metric-panel">
          <div class="panel-header">
            <h3>Open findings</h3>
            <span class="muted">Across all assessments</span>
          </div>
          <strong class="metric-value"><?= (int) $summary['open_findings'] ?></strong>
          <div class="mini-chart mini-a"></div>
        </article>

        <article class="panel metric-panel">
          <div class="panel-header">
            <h3>Critical / High</h3>
            <span class="muted">Priority backlog</span>
          </div>
          <strong class="metric-value"><?= (int) $summary['critical'] ?> / <?= (int) $summary['high'] ?></strong>
          <div class="stack compact">
            <div class="stack-row"><span>Critical</span><div class="bar"><i style="width:82%"></i></div></div>
            <div class="stack-row"><span>High</span><div class="bar"><i style="width:64%"></i></div></div>
          </div>
        </article>

        <article class="panel chart-panel">
          <div class="panel-header">
            <h3>Risk trend</h3>
            <span class="muted">Last 6 scans</span>
          </div>
          <div class="line-grid">
            <span></span><span></span><span></span><span></span><span></span>
          </div>
          <div class="trend-lines">
            <div class="trend-line t1"></div>
            <div class="trend-line t2"></div>
            <div class="trend-line t3"></div>
          </div>
        </article>

        <article class="panel chart-panel">
          <div class="panel-header">
            <h3>Quality health</h3>
            <span class="muted"><?= e((string) $summary['quality_gate']) ?></span>
          </div>
          <div class="score-ring">
            <div class="score-ring-inner">
              <strong><?= (int) $summary['coverage'] ?>%</strong>
              <span>Coverage</span>
            </div>
          </div>
        </article>

        <article class="panel wide">
          <div class="panel-header">
            <h3>Recent scans</h3>
            <span class="muted">SonarQube, ZAP, and dependency-check are normalized into one timeline</span>
          </div>
          <div class="activity-list">
            <?php foreach ($scanRuns as $run): ?>
              <div class="activity-row">
                <div class="activity-dot"></div>
                <div class="activity-main">
                  <strong><?= e($run['tool_name']) ?></strong>
                  <span><?= e((string) ($run['summary'] ?? '-')) ?></span>
                </div>
                <div class="activity-meta">
                  <span class="tag"><?= e(strtoupper((string) $run['scan_type'])) ?></span>
                  <span class="tag tag-okay"><?= e((string) $run['status']) ?></span>
                  <small><?= e((string) ($run['completed_at'] ?? '-')) ?></small>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </article>

        <article class="panel wide">
          <div class="panel-header">
            <h3>Top findings</h3>
            <span class="muted">Sorted by severity for executive review</span>
          </div>
          <div class="finding-list">
            <?php foreach ($findings as $finding): ?>
              <article class="finding-card <?= e(severityClass((string) $finding['severity'])) ?>">
                <div class="finding-head">
                  <strong><?= e((string) $finding['title']) ?></strong>
                  <span class="tag"><?= e(strtoupper((string) $finding['severity'])) ?></span>
                </div>
                <p><?= e((string) $finding['description']) ?></p>
                <div class="finding-foot">
                  <span><?= e((string) $finding['category']) ?></span>
                  <span><?= e((string) ($finding['file_path'] ?? 'n/a')) ?><?= !empty($finding['line_number']) ? ':' . (int) $finding['line_number'] : '' ?></span>
                </div>
              </article>
            <?php endforeach; ?>
          </div>
        </article>
      </section>
    </main>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
