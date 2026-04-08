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

        try {
            $integrationStmt = $pdo->prepare('SELECT * FROM integrations WHERE project_id = ? ORDER BY created_at DESC');
            $integrationStmt->execute([$project['id']]);
            $integrations = $integrationStmt->fetchAll();
        } catch (Throwable $e) {
            $integrations = sampleDashboard()['integrations'];
        }

        $findingStmt = $pdo->prepare('SELECT f.* FROM findings f INNER JOIN scan_runs s ON s.id = f.scan_run_id WHERE s.project_id = ? ORDER BY FIELD(f.severity, "critical","high","medium","low","info"), f.created_at DESC');
        $findingStmt->execute([$project['id']]);
        $findings = $findingStmt->fetchAll();

        try {
            $assetStmt = $pdo->prepare('SELECT * FROM attack_surface_assets WHERE project_id = ? ORDER BY created_at DESC');
            $assetStmt->execute([$project['id']]);
            $assets = $assetStmt->fetchAll();
        } catch (Throwable $e) {
            $assets = oasmAssetSamples();
        }
    } else {
        $useSample = true;
    }
}

if ($useSample) {
    $dashboard = sampleDashboard();
    $project = $dashboard['project'];
    $scanRuns = $dashboard['scan_runs'];
    $integrations = $dashboard['integrations'];
    $findings = $dashboard['findings'];
    $assets = oasmAssetSamples();
}

$reviewError = $_SESSION['review_error'] ?? null;
$reviewSuccess = $_SESSION['review_success'] ?? null;
unset($_SESSION['review_error'], $_SESSION['review_success']);

$critical = count(array_filter($findings, fn($f) => $f['severity'] === 'critical'));
$high = count(array_filter($findings, fn($f) => $f['severity'] === 'high'));
$medium = count(array_filter($findings, fn($f) => $f['severity'] === 'medium'));
$low = count(array_filter($findings, fn($f) => $f['severity'] === 'low'));
$open = count($findings);
$toolReady = count(array_filter($integrations, fn($tool) => ($tool['status'] ?? '') === 'ready'));
$toolTotal = count($integrations);
$pentestService = null;
$oasmService = null;
foreach ($integrations as $integration) {
    if (($integration['name'] ?? '') === 'Python Pentest Suite') {
        $pentestService = $integration;
    }
    if (($integration['name'] ?? '') === 'Open Attack Surface Management') {
        $oasmService = $integration;
    }
}
$domainCards = [
    ['label' => 'SAST', 'count' => count(array_filter($scanRuns, fn($run) => ($run['scan_type'] ?? '') === 'sast')), 'hint' => 'Static code review'],
    ['label' => 'DAST', 'count' => count(array_filter($scanRuns, fn($run) => ($run['scan_type'] ?? '') === 'dast' || ($run['scan_type'] ?? '') === 'zap')), 'hint' => 'Dynamic web testing'],
    ['label' => 'SCA', 'count' => count(array_filter($scanRuns, fn($run) => ($run['scan_type'] ?? '') === 'sca')), 'hint' => 'Dependency analysis'],
    ['label' => 'Mobile', 'count' => count(array_filter($integrations, fn($tool) => ($tool['tool_category'] ?? '') === 'mobile')), 'hint' => 'MobSF / APK review'],
    ['label' => 'Pentest', 'count' => count(array_filter($integrations, fn($tool) => ($tool['tool_category'] ?? '') === 'pentest')), 'hint' => 'Authorized testing'],
    ['label' => 'Automation', 'count' => count(array_filter($integrations, fn($tool) => ($tool['tool_category'] ?? '') === 'automation')), 'hint' => 'Workflow helpers'],
];
$user = currentUser();
$role = currentUserRole();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Report - <?= e((string) $project['name']) ?></title>
  <link rel="icon" href="assets/img/favicon.ico">
  <link rel="stylesheet" href="assets/css/app.css">
  <?php if (isset($_GET['print'])): ?><script>window.addEventListener('load', () => window.print());</script><?php endif; ?>
</head>
<body class="report-page">
  <div class="app-shell checklist-shell report-shell-shell">
    <aside class="sidebar">
      <div class="brand-lockup sidebar-brand">
        <img src="<?= e((string) ($project['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">cyber-Security</p>
          <strong>Executive report</strong>
        </div>
      </div>
      <nav class="side-nav">
        <a class="side-link" href="home.php">Dashboard</a>
        <a class="side-link" href="audit.php">Audit</a>
        <a class="side-link" href="checklist.php">Checklist</a>
        <a class="side-link" href="oasm.php">Open ASM</a>
        <a class="side-link active" href="report.php">Report</a>
        <a class="side-link" href="deliverables.php">Deliverables</a>
      </nav>
      <div class="sidebar-card">
        <span class="tag tag-okay">Executive view</span>
        <h3><?= e((string) $project['name']) ?></h3>
        <p><?= e((string) $project['client_name']) ?></p>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar pro-topbar">
        <div class="search-pill">
          <span class="search-icon" aria-hidden="true"></span>
          <input type="text" placeholder="Search findings, tools, assets, and checklist data" aria-label="Search report">
        </div>
        <div class="topbar-actions">
          <span class="status-chip"><?= e(ucfirst($role)) ?></span>
          <a class="button ghost" href="report.php?print=1">Download PDF</a>
          <a class="button ghost" href="export.php?format=doc">Word</a>
          <a class="button ghost" href="export.php?format=xls">Excel</a>
          <a class="button ghost" href="export.php?format=csv">CSV</a>
          <a class="button ghost" href="export.php?format=json">JSON</a>
          <a class="button" href="home.php">Back to dashboard</a>
          <span class="user-badge"><?= e(strtoupper(substr((string) ($user['display_name'] ?? 'A'), 0, 2))) ?></span>
        </div>
      </header>

      <section class="hero-strip checklist-hero">
        <div class="report-brand">
          <div class="brand-lockup">
            <img src="<?= e((string) ($project['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
            <div class="report-brand-copy">
              <p class="eyebrow">Executive security report</p>
              <h1><?= e((string) $project['name']) ?></h1>
              <p class="subhead">Prepared for <?= e((string) $project['client_name']) ?>. This consolidated report brings together application security, code quality, and dependency risk in a single decision-ready view.</p>
            </div>
          </div>
        </div>
        <div class="hero-actions">
          <a class="button ghost" href="audit.php">Audit</a>
          <a class="button ghost" href="checklist.php">Checklist</a>
          <a class="button ghost" href="oasm.php">Open ASM</a>
          <a class="button" href="deliverables.php">Deliverables</a>
        </div>
      </section>

    <?php if ($reviewSuccess): ?><div class="notice success"><?= e((string) $reviewSuccess) ?></div><?php endif; ?>
    <?php if ($reviewError): ?><div class="notice danger"><?= e((string) $reviewError) ?></div><?php endif; ?>

      <section class="report-summary">
      <div class="summary-card"><span>Open findings</span><strong><?= (int) $open ?></strong></div>
      <div class="summary-card"><span>Critical</span><strong><?= (int) $critical ?></strong></div>
      <div class="summary-card"><span>High</span><strong><?= (int) $high ?></strong></div>
      <div class="summary-card"><span>Medium</span><strong><?= (int) $medium ?></strong></div>
      <div class="summary-card"><span>Low</span><strong><?= (int) $low ?></strong></div>
      <div class="summary-card"><span>Tools up</span><strong><?= (int) $toolReady ?>/<?= (int) $toolTotal ?></strong></div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Assessment domains</h3>
        <span class="muted">Static, dynamic, mobile, and pentest coverage</span>
      </div>
      <div class="access-grid">
        <?php foreach ($domainCards as $card): ?>
          <div>
            <span><?= e($card['label']) ?></span>
            <strong><?= (int) $card['count'] ?></strong>
            <small class="muted"><?= e($card['hint']) ?></small>
          </div>
        <?php endforeach; ?>
      </div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Assessment scope</h3>
      </div>
      <div class="scope-grid">
        <div><span>Repository</span><strong><?= e((string) ($project['repository_url'] ?? 'n/a')) ?></strong></div>
        <div><span>Target</span><strong><?= e((string) ($project['target_url'] ?? 'n/a')) ?></strong></div>
        <div><span>Coverage model</span><strong>SAST, DAST, SCA, MobSF, and Python pentest validation</strong></div>
        <div><span>Delivery</span><strong>HTML report, printable view, and MySQL archive</strong></div>
      </div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Client access</h3>
        <span class="muted">Portal, source repository, and credentials reference</span>
      </div>
      <div class="access-grid">
        <div><span>Portal</span><strong><?= e((string) ($project['portal_url'] ?? $project['target_url'] ?? 'n/a')) ?></strong></div>
        <div><span>Source URL</span><strong><?= e((string) ($project['source_url'] ?? 'n/a')) ?></strong></div>
        <div><span>Source user</span><strong><?= e((string) ($project['source_username'] ?? 'n/a')) ?></strong></div>
        <div><span>Password note</span><strong><?= e((string) ($project['source_password_hint'] ?? 'n/a')) ?></strong></div>
      </div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Open ASM</h3>
        <span class="muted">Asset exposure overview from the OASM module</span>
      </div>
      <div class="access-grid">
        <div><span>Total assets</span><strong><?= (int) count($assets) ?></strong></div>
        <div><span>Public</span><strong><?= (int) count(array_filter($assets, fn($asset) => ($asset['exposure'] ?? '') === 'public')) ?></strong></div>
        <div><span>Internal</span><strong><?= (int) count(array_filter($assets, fn($asset) => ($asset['exposure'] ?? '') === 'internal')) ?></strong></div>
        <div><span>Reviewed</span><strong><?= (int) count(array_filter($assets, fn($asset) => ($asset['status'] ?? '') === 'reviewed')) ?></strong></div>
      </div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Tool health</h3>
        <span class="muted">Up, configured, and disabled tools with logos</span>
      </div>
      <div class="finding-list">
        <?php foreach ($integrations as $integration): ?>
          <article class="finding-card <?= e(integrationStatusClass((string) ($integration['status'] ?? 'configured'))) ?>">
            <div class="finding-head">
              <div class="brand-lockup">
                <img src="<?= e((string) ($integration['tool_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="<?= e((string) $integration['name']) ?>" class="brand-mark">
                <div>
                  <strong><?= e((string) $integration['name']) ?></strong>
                  <div class="finding-badges">
                    <span class="tag"><?= e(toolCategoryLabel((string) ($integration['tool_category'] ?? 'automation'))) ?></span>
                    <span class="tag"><?= e(strtoupper((string) ($integration['connection_type'] ?? 'manual'))) ?></span>
                  </div>
                </div>
              </div>
              <div class="finding-badges">
                <span class="tag <?= e(integrationStatusClass((string) $integration['status'])) ?>"><?= e(strtoupper((string) $integration['status'])) ?></span>
              </div>
            </div>
            <p><?= e((string) ($integration['description'] ?? '')) ?></p>
            <div class="finding-foot">
              <span><?= e((string) ($integration['endpoint_url'] ?? 'n/a')) ?></span>
              <span><?= e((string) ($integration['status'] === 'ready' ? 'up' : 'needs review')) ?></span>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
      </section>

      <section class="report-summary">
      <?php $pentestHealth = toolHealth((string) ($pentestService['endpoint_url'] ?? '')); ?>
      <?php $oasmHealth = toolHealth((string) ($oasmService['endpoint_url'] ?? '')); ?>
      <div class="summary-card"><span>Python pentest</span><strong><?= e($pentestHealth['label']) ?></strong></div>
      <div class="summary-card"><span>OASM</span><strong><?= e($oasmHealth['label']) ?></strong></div>
      <div class="summary-card"><span>Pentest endpoint</span><strong><?= e((string) ($pentestHealth['detail'] ?? 'n/a')) ?></strong></div>
      <div class="summary-card"><span>OASM endpoint</span><strong><?= e((string) ($oasmHealth['detail'] ?? 'n/a')) ?></strong></div>
      <div class="summary-card"><span>Checklist sections</span><strong><?= (int) count(pentestChecklist()) ?></strong></div>
      <div class="summary-card"><span>ASM assets</span><strong><?= (int) count($assets) ?></strong></div>
      </section>

      <section class="panel">
      <div class="panel-header">
        <h3>Python pentest playbook</h3>
        <span class="muted">Safe validation workflow for authorized testing only</span>
      </div>
      <div class="activity-list">
        <?php foreach (pentestPlaybook() as $item): ?>
          <div class="activity-row">
            <div class="activity-dot"></div>
            <div class="activity-main">
              <strong><?= e((string) $item['title']) ?></strong>
              <span><?= e((string) $item['summary']) ?></span>
            </div>
            <div class="activity-meta">
              <span class="tag tag-okay">Python</span>
              <span class="tag">Validation</span>
            </div>
          </div>
        <?php endforeach; ?>
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
        <h3>Checklist and ASM export snapshot</h3>
        <span class="muted">Included in Word and Excel exports for client delivery</span>
      </div>
      <div class="access-grid">
        <div><span>Checklist sections</span><strong><?= (int) count(pentestChecklist()) ?></strong></div>
        <div><span>OASM assets</span><strong><?= (int) count($assets) ?></strong></div>
        <div><span>Python pentest</span><strong>Safe validation playbook</strong></div>
        <div><span>Delivery</span><strong>DOC, XLS, CSV, JSON, PDF-ready</strong></div>
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
            <?php if (!empty($finding['ai_issue_summary'])): ?>
              <p class="ai-summary"><strong>AI issue summary:</strong> <?= e((string) $finding['ai_issue_summary']) ?></p>
            <?php endif; ?>
            <?php if (!empty($finding['ai_summary'])): ?>
              <p class="ai-summary"><strong>AI triage:</strong> <?= e((string) $finding['ai_summary']) ?><?php if (!empty($finding['ai_confidence'])): ?> (<?= (int) $finding['ai_confidence'] ?>%)<?php endif; ?></p>
            <?php endif; ?>
            <?php if (!empty($finding['ai_remediation'])): ?>
              <p class="recommendation"><strong>AI remediation:</strong> <?= e((string) $finding['ai_remediation']) ?></p>
            <?php endif; ?>
            <?php if (!empty($finding['validation_notes'])): ?>
              <p class="ai-summary"><strong>Validation evidence:</strong> <?= e((string) $finding['validation_notes']) ?></p>
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
                <span>AI issue summary</span>
                <textarea name="ai_issue_summary" rows="2" placeholder="What the AI detected"><?= e((string) ($finding['ai_issue_summary'] ?? '')) ?></textarea>
              </label>
              <label class="full">
                <span>Analyst comment</span>
                <textarea name="analyst_comment" rows="3" placeholder="Why is this marked false positive or what should be done next?"><?= e((string) ($finding['analyst_comment'] ?? '')) ?></textarea>
              </label>
              <label class="full">
                <span>AI summary</span>
                <textarea name="ai_summary" rows="2" placeholder="AI triage note"><?= e((string) ($finding['ai_summary'] ?? '')) ?></textarea>
              </label>
              <label class="full">
                <span>AI remediation</span>
                <textarea name="ai_remediation" rows="2" placeholder="Recommended fix in one or two lines"><?= e((string) ($finding['ai_remediation'] ?? '')) ?></textarea>
              </label>
              <label class="full">
                <span>Validation evidence</span>
                <textarea name="validation_notes" rows="2" placeholder="Safe reproduction notes, screenshots, or validation context"><?= e((string) ($finding['validation_notes'] ?? '')) ?></textarea>
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
    </main>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
