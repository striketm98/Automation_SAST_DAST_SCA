<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

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

        $assetStmt = $pdo->prepare('SELECT * FROM attack_surface_assets WHERE project_id = ? ORDER BY created_at DESC');
        $assetStmt->execute([$project['id']]);
        $assets = $assetStmt->fetchAll();
    } else {
        $dashboard = sampleDashboard();
        $project = $dashboard['project'];
        $scanRuns = $dashboard['scan_runs'];
        $findings = $dashboard['findings'];
        $assets = oasmAssetSamples();
    }
} else {
    $dashboard = sampleDashboard();
    $project = $dashboard['project'];
    $scanRuns = $dashboard['scan_runs'];
    $findings = $dashboard['findings'];
    $assets = oasmAssetSamples();
}

$critical = count(array_filter($findings, fn($f) => $f['severity'] === 'critical'));
$high = count(array_filter($findings, fn($f) => $f['severity'] === 'high'));
$open = count($findings);
$pentestSections = pentestChecklist();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Deliverables</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
  <?php if (isset($_GET['print'])): ?><script>window.addEventListener('load', () => window.print());</script><?php endif; ?>
</head>
<body>
  <div class="page-shell">
    <header class="report-header">
      <div class="brand-lockup">
        <img src="<?= e((string) ($project['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
        <p class="eyebrow">Client deliverables</p>
        <h1><?= e((string) $project['name']) ?></h1>
        <p class="subhead">One printable bundle for findings, OASM inventory, and the pentest checklist in a polished client-facing format.</p>
      </div>
      <div class="report-actions">
        <a class="button ghost" href="deliverables.php?print=1">Print</a>
        <a class="button ghost" href="audit.php">Audit</a>
        <a class="button ghost" href="report.php">Report</a>
        <a class="button ghost" href="oasm.php">Open ASM</a>
        <a class="button" href="home.php">Dashboard</a>
      </div>
    </header>

    <section class="report-summary">
      <div class="summary-card"><span>Open findings</span><strong><?= (int) $open ?></strong></div>
      <div class="summary-card"><span>Critical</span><strong><?= (int) $critical ?></strong></div>
      <div class="summary-card"><span>High</span><strong><?= (int) $high ?></strong></div>
      <div class="summary-card"><span>Checklist sections</span><strong><?= (int) count($pentestSections) ?></strong></div>
      <div class="summary-card"><span>ASM assets</span><strong><?= (int) count($assets) ?></strong></div>
      <div class="summary-card"><span>Scans</span><strong><?= (int) count($scanRuns) ?></strong></div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h3>Deliverable scope</h3>
        <span class="muted">Executive summary ready for client review</span>
      </div>
      <div class="scope-grid">
        <div><span>Assessment</span><strong>SAST, DAST, SCA, Mobile, Pentest</strong></div>
        <div><span>Outputs</span><strong>Report, checklist, OASM inventory</strong></div>
        <div><span>Format</span><strong>Printable, shareable, export-ready</strong></div>
        <div><span>Brand</span><strong>cyber-Security</strong></div>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Pentest checklist</h3>
        <span class="muted">Safe validation points</span>
      </div>
      <div class="checklist-grid">
        <?php foreach ($pentestSections as $group): ?>
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
        <h3>Open ASM inventory</h3>
        <span class="muted">Tracked assets for the approved scope</span>
      </div>
      <div class="finding-list">
        <?php foreach ($assets as $asset): ?>
          <article class="finding-card <?= e($asset['exposure'] === 'public' ? 'sev-high' : 'sev-info') ?>">
            <div class="finding-head">
              <strong><?= e((string) $asset['asset_name']) ?></strong>
              <div class="finding-badges">
                <span class="tag"><?= e(strtoupper((string) $asset['asset_type'])) ?></span>
                <span class="tag"><?= e(strtoupper((string) $asset['exposure'])) ?></span>
                <span class="tag"><?= e(strtoupper((string) $asset['status'])) ?></span>
              </div>
            </div>
            <p><?= e((string) ($asset['notes'] ?? '')) ?></p>
            <div class="finding-foot">
              <span><?= e((string) ($asset['asset_url'] ?? 'n/a')) ?></span>
              <span>OASM</span>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Top findings</h3>
        <span class="muted">Client-facing list of priority items</span>
      </div>
      <div class="finding-list">
        <?php foreach ($findings as $finding): ?>
          <article class="finding-card <?= e(severityClass((string) $finding['severity'])) ?>">
            <div class="finding-head">
              <strong><?= e((string) $finding['title']) ?></strong>
              <span class="tag"><?= e(strtoupper((string) $finding['severity'])) ?></span>
            </div>
            <p><?= e((string) $finding['description']) ?></p>
            <p class="recommendation"><strong>Remediation:</strong> <?= e((string) $finding['recommendation']) ?></p>
          </article>
        <?php endforeach; ?>
      </div>
    </section>
  </div>
</body>
</html>
