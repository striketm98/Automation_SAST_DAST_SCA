<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();

if ($pdo) {
    $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    if ($project) {
        try {
            $scanStmt = $pdo->prepare('SELECT * FROM scan_runs WHERE project_id = ? ORDER BY created_at DESC');
            $scanStmt->execute([$project['id']]);
            $scanRuns = $scanStmt->fetchAll();
        } catch (Throwable $e) {
            $scanRuns = sampleDashboard()['scan_runs'];
        }

        try {
            $findingStmt = $pdo->prepare('SELECT f.* FROM findings f INNER JOIN scan_runs s ON s.id = f.scan_run_id WHERE s.project_id = ? ORDER BY FIELD(f.severity, "critical","high","medium","low","info"), f.created_at DESC');
            $findingStmt->execute([$project['id']]);
            $findings = $findingStmt->fetchAll();
        } catch (Throwable $e) {
            $findings = sampleDashboard()['findings'];
        }

        try {
            $assetStmt = $pdo->prepare('SELECT * FROM attack_surface_assets WHERE project_id = ? ORDER BY created_at DESC');
            $assetStmt->execute([$project['id']]);
            $assets = $assetStmt->fetchAll();
        } catch (Throwable $e) {
            $assets = oasmAssetSamples();
        }
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
$user = currentUser();
$role = currentUserRole();
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
<body class="checklist-page">
  <div class="app-shell checklist-shell">
    <aside class="sidebar">
      <div class="brand-lockup sidebar-brand">
        <img src="<?= e((string) ($project['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">cyber-Security</p>
          <strong>Deliverables hub</strong>
        </div>
      </div>
      <nav class="side-nav">
        <a class="side-link" href="home.php">Dashboard</a>
        <a class="side-link" href="scan_jobs.php">Scan jobs</a>
        <a class="side-link" href="audit.php">Audit</a>
        <a class="side-link" href="checklist.php">Checklist</a>
        <a class="side-link" href="oasm.php">Open ASM</a>
        <a class="side-link" href="report.php">Report</a>
        <a class="side-link active" href="deliverables.php">Deliverables</a>
      </nav>
      <div class="sidebar-card">
        <span class="tag tag-okay">Client pack</span>
        <h3><?= e((string) $project['name']) ?></h3>
        <p><?= e((string) $project['client_name']) ?></p>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar pro-topbar">
        <div class="search-pill">
          <span class="search-icon" aria-hidden="true"></span>
          <input type="text" placeholder="Search deliverables, findings, assets, and checklist sections" aria-label="Search deliverables">
        </div>
        <div class="topbar-actions">
          <span class="status-chip"><?= e(ucfirst($role)) ?></span>
          <a class="button ghost" href="deliverables.php?print=1">Print</a>
          <a class="button ghost" href="report.php">Report</a>
          <a class="button" href="home.php">Dashboard</a>
          <span class="user-badge"><?= e(strtoupper(substr((string) ($user['display_name'] ?? 'A'), 0, 2))) ?></span>
        </div>
      </header>

      <section class="hero-strip checklist-hero">
        <div>
          <p class="eyebrow">Client deliverables</p>
          <h1><?= e((string) $project['name']) ?></h1>
          <p class="subhead">One printable bundle for findings, OASM inventory, and the pentest checklist in a polished client-facing format.</p>
        </div>
        <div class="hero-actions">
          <a class="button ghost" href="audit.php">Audit</a>
          <a class="button ghost" href="checklist.php">Checklist</a>
          <a class="button ghost" href="oasm.php">Open ASM</a>
          <a class="button" href="report.php">Executive report</a>
        </div>
      </section>

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
    </main>
  </div>
</body>
</html>
