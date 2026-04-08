<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();
$useSample = !$pdo;

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
        $useSample = true;
    }
}

if ($useSample) {
    $dashboard = sampleDashboard();
    $project = $dashboard['project'];
    $scanRuns = $dashboard['scan_runs'];
    $findings = $dashboard['findings'];
}

$critical = count(array_filter($findings, fn($f) => $f['severity'] === 'critical'));
$high = count(array_filter($findings, fn($f) => $f['severity'] === 'high'));
$medium = count(array_filter($findings, fn($f) => $f['severity'] === 'medium'));
$low = count(array_filter($findings, fn($f) => $f['severity'] === 'low'));
$open = count($findings);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Report - <?= e((string) $project['name']) ?></title>
  <link rel="icon" href="assets/img/favicon.ico">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body class="report-page">
  <div class="page-shell report-shell">
    <header class="report-header">
      <div class="brand-lockup">
        <img src="assets/img/favicon.ico" alt="cyber-Security logo" class="brand-mark">
        <p class="eyebrow">Executive security report</p>
        <h1><?= e((string) $project['name']) ?></h1>
        <p class="subhead">Prepared for <?= e((string) $project['client_name']) ?>. This consolidated report combines code quality, application security, and dependency risk into one view.</p>
      </div>
      <div class="report-actions">
        <button class="button ghost" onclick="window.print()">Print / PDF</button>
        <a class="button ghost" href="export.php?format=csv">Export CSV</a>
        <a class="button ghost" href="export.php?format=json">Export JSON</a>
        <a class="button" href="index.php">Back to dashboard</a>
      </div>
    </header>

    <section class="report-summary">
      <div class="summary-card"><span>Open findings</span><strong><?= (int) $open ?></strong></div>
      <div class="summary-card"><span>Critical</span><strong><?= (int) $critical ?></strong></div>
      <div class="summary-card"><span>High</span><strong><?= (int) $high ?></strong></div>
      <div class="summary-card"><span>Medium</span><strong><?= (int) $medium ?></strong></div>
      <div class="summary-card"><span>Low</span><strong><?= (int) $low ?></strong></div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h3>Assessment scope</h3>
      </div>
      <div class="scope-grid">
        <div><span>Repository</span><strong><?= e((string) ($project['repository_url'] ?? 'n/a')) ?></strong></div>
        <div><span>Target</span><strong><?= e((string) ($project['target_url'] ?? 'n/a')) ?></strong></div>
        <div><span>Coverage model</span><strong>SAST + DAST + SonarQube + SCA</strong></div>
        <div><span>Delivery</span><strong>HTML report, printable view, MySQL archive</strong></div>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Findings</h3>
      </div>
      <div class="report-findings">
        <?php foreach ($findings as $finding): ?>
          <article class="finding-card <?= e(severityClass((string) $finding['severity'])) ?>">
            <div class="finding-head">
              <strong><?= e((string) $finding['title']) ?></strong>
              <span class="tag"><?= e(strtoupper((string) $finding['severity'])) ?></span>
            </div>
            <p><?= e((string) $finding['description']) ?></p>
            <p class="recommendation"><strong>Recommendation:</strong> <?= e((string) $finding['recommendation']) ?></p>
            <div class="finding-foot">
              <span><?= e((string) $finding['category']) ?></span>
              <span><?= e((string) ($finding['file_path'] ?? 'n/a')) ?><?= !empty($finding['line_number']) ? ':' . (int) $finding['line_number'] : '' ?></span>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Scan timeline</h3>
      </div>
      <div class="timeline">
        <?php foreach ($scanRuns as $run): ?>
          <div class="timeline-item">
            <div class="timeline-dot"></div>
            <div class="timeline-content">
              <strong><?= e((string) $run['tool_name']) ?></strong>
              <p><?= e((string) ($run['summary'] ?? '')) ?></p>
              <span><?= e((string) ($run['completed_at'] ?? '')) ?></span>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </section>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
