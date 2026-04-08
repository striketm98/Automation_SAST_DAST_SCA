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

$reviewError = $_SESSION['review_error'] ?? null;
$reviewSuccess = $_SESSION['review_success'] ?? null;
unset($_SESSION['review_error'], $_SESSION['review_success']);

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
        <img src="assets/img/cyber-logo.png" alt="cyber-Security logo" class="brand-mark">
        <p class="eyebrow">Executive security report</p>
        <h1><?= e((string) $project['name']) ?></h1>
        <p class="subhead">Prepared for <?= e((string) $project['client_name']) ?>. This consolidated report brings together application security, code quality, and dependency risk in a single decision-ready view.</p>
      </div>
      <div class="report-actions">
        <button class="button ghost" onclick="window.print()">Print / PDF</button>
        <a class="button ghost" href="export.php?format=csv">Export CSV</a>
        <a class="button ghost" href="export.php?format=json">Export JSON</a>
        <a class="button" href="index.php">Back to dashboard</a>
      </div>
    </header>

    <?php if ($reviewSuccess): ?><div class="notice success"><?= e((string) $reviewSuccess) ?></div><?php endif; ?>
    <?php if ($reviewError): ?><div class="notice danger"><?= e((string) $reviewError) ?></div><?php endif; ?>

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
        <div><span>Coverage model</span><strong>SAST, DAST, SonarQube, ZAP, and SCA</strong></div>
        <div><span>Delivery</span><strong>HTML report, printable view, and MySQL archive</strong></div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h3>CWE coverage</h3>
        <span class="muted">AI-assisted triage included</span>
      </div>
      <div class="tag-cloud">
        <?php foreach (cweCatalog() as $cwe => $label): ?>
          <span class="tag"><?= e($cwe . ' ' . $label) ?></span>
        <?php endforeach; ?>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Findings</h3>
        <span class="muted">Use the review panel to mark false positives, add comments, and store AI notes.</span>
      </div>
      <div class="report-findings">
        <?php foreach ($findings as $finding): ?>
          <article class="finding-card <?= e(severityClass((string) $finding['severity'])) ?>">
            <div class="finding-head">
              <strong><?= e((string) $finding['title']) ?></strong>
              <div class="finding-badges">
                <span class="tag <?= e(findingStatusClass((string) ($finding['status'] ?? 'open'))) ?>"><?= e(strtoupper(str_replace('_', ' ', (string) ($finding['status'] ?? 'open')))) ?></span>
                <span class="tag"><?= e(strtoupper((string) $finding['severity'])) ?></span>
              </div>
            </div>
            <p><?= e((string) $finding['description']) ?></p>
            <p class="recommendation"><strong>Recommendation:</strong> <?= e((string) $finding['recommendation']) ?></p>
            <?php if (!empty($finding['ai_summary'])): ?>
              <p class="ai-summary"><strong>AI triage:</strong> <?= e((string) $finding['ai_summary']) ?><?php if (!empty($finding['ai_confidence'])): ?> (<?= (int) $finding['ai_confidence'] ?>%)<?php endif; ?></p>
            <?php endif; ?>
            <div class="finding-foot">
              <span><?= e((string) $finding['category']) ?></span>
              <span><?= e((string) ($finding['file_path'] ?? 'n/a')) ?><?= !empty($finding['line_number']) ? ':' . (int) $finding['line_number'] : '' ?></span>
            </div>
            <form class="review-form" method="post" action="review.php">
              <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
              <input type="hidden" name="finding_id" value="<?= (int) $finding['id'] ?>">
              <label>
                <span>Status</span>
                <select name="status">
                  <option value="open" <?= (($finding['status'] ?? 'open') === 'open') ? 'selected' : '' ?>>Open</option>
                  <option value="false_positive" <?= (($finding['status'] ?? '') === 'false_positive') ? 'selected' : '' ?>>False positive</option>
                  <option value="accepted_risk" <?= (($finding['status'] ?? '') === 'accepted_risk') ? 'selected' : '' ?>>Accepted risk</option>
                  <option value="resolved" <?= (($finding['status'] ?? '') === 'resolved') ? 'selected' : '' ?>>Resolved</option>
                </select>
              </label>
              <label>
                <span>CWE</span>
                <input type="text" name="cwe_id" value="<?= e((string) ($finding['cwe_id'] ?? '')) ?>" placeholder="CWE-78">
              </label>
              <label class="full">
                <span>Analyst comment</span>
                <textarea name="analyst_comment" rows="3" placeholder="Why is this marked false positive or what should be done next?"><?= e((string) ($finding['analyst_comment'] ?? '')) ?></textarea>
              </label>
              <label class="full">
                <span>AI summary</span>
                <textarea name="ai_summary" rows="2" placeholder="AI triage note"><?= e((string) ($finding['ai_summary'] ?? '')) ?></textarea>
              </label>
              <label>
                <span>AI confidence</span>
                <input type="number" name="ai_confidence" min="0" max="100" value="<?= (int) ($finding['ai_confidence'] ?? 0) ?>">
              </label>
              <div class="review-actions">
                <button class="button ghost" type="submit">Save review</button>
              </div>
            </form>
          </article>
        <?php endforeach; ?>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Scan timeline</h3>
        <span class="muted">Includes safe labels for injection-style findings without exploit detail</span>
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
