<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();
$project = null;
$scanRuns = [];
$findings = [];
$assets = [];
$integrations = [];
$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$pdo) {
        $_SESSION['audit_error'] = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $_SESSION['audit_error'] = 'Your session expired. Please try again.';
    } else {
        $findingId = (int) ($_POST['finding_id'] ?? 0);
        $action = (string) ($_POST['action'] ?? '');
        if ($findingId <= 0 || !in_array($action, ['claim', 'suppress', 'unsuppress'], true)) {
            $_SESSION['audit_error'] = 'Invalid audit action.';
        } else {
            try {
                $user = currentUser() ?? [];
                $actor = (string) ($user['display_name'] ?? $user['email'] ?? 'analyst');
                if ($action === 'claim') {
                    $stmt = $pdo->prepare('UPDATE findings SET claim_state = ?, claimed_by = ?, claimed_at = NOW() WHERE id = ?');
                    $stmt->execute(['claimed', $actor, $findingId]);
                    $_SESSION['audit_message'] = 'Finding claimed.';
                } elseif ($action === 'suppress') {
                    $stmt = $pdo->prepare('UPDATE findings SET status = ? WHERE id = ?');
                    $stmt->execute(['false_positive', $findingId]);
                    $_SESSION['audit_message'] = 'Finding suppressed as false positive.';
                } else {
                    $stmt = $pdo->prepare('UPDATE findings SET status = ? WHERE id = ?');
                    $stmt->execute(['open', $findingId]);
                    $_SESSION['audit_message'] = 'Finding unsuppressed and returned to open.';
                }
            } catch (Throwable $e) {
                $_SESSION['audit_error'] = 'Database schema is being initialized. Please refresh and try again.';
            }
            header('Location: audit.php?finding=' . $findingId);
            exit;
        }
    }
}

if ($pdo) {
    $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    if ($project) {
        $scanStmt = $pdo->prepare('SELECT * FROM scan_runs WHERE project_id = ? ORDER BY created_at DESC');
        $scanStmt->execute([$project['id']]);
        $scanRuns = $scanStmt->fetchAll();

        $findingStmt = $pdo->prepare('SELECT f.* FROM findings f INNER JOIN scan_runs s ON s.id = f.scan_run_id WHERE s.project_id = ? ORDER BY FIELD(f.severity, "critical","high","medium","low","info"), f.created_at DESC');
        $findingStmt->execute([$project['id']]);
        $findings = $findingStmt->fetchAll();

        try {
            $integrationStmt = $pdo->prepare('SELECT * FROM integrations WHERE project_id = ? ORDER BY created_at DESC');
            $integrationStmt->execute([$project['id']]);
            $integrations = $integrationStmt->fetchAll();
            if (!$integrations) {
                $integrations = sampleDashboard()['integrations'];
            }
        } catch (Throwable $e) {
            $integrations = sampleDashboard()['integrations'];
        }

        try {
            $assetStmt = $pdo->prepare('SELECT * FROM attack_surface_assets WHERE project_id = ? ORDER BY created_at DESC');
            $assetStmt->execute([$project['id']]);
            $assets = $assetStmt->fetchAll();
        } catch (Throwable $e) {
            $assets = oasmAssetSamples();
        }
    }
}

if (!$project) {
    $dashboard = sampleDashboard();
    $project = $dashboard['project'];
    $scanRuns = $dashboard['scan_runs'];
    $findings = $dashboard['findings'];
    $integrations = $dashboard['integrations'];
    $assets = oasmAssetSamples();
}

$auditRows = [];
foreach ($findings as $finding) {
    $scanType = strtolower((string) ($finding['category'] ?? 'sast'));
    if ($scanType === 'sast') {
        $analysisType = 'SAST';
    } elseif ($scanType === 'dast') {
        $analysisType = 'DAST';
    } elseif ($scanType === 'sca') {
        $analysisType = 'SCA';
    } elseif (str_contains(strtolower((string) $finding['category']), 'mobile')) {
        $analysisType = 'Mobile';
    } else {
        $analysisType = 'PT';
    }

    $auditRows[] = [
        'kind' => 'finding',
        'id' => (int) $finding['id'],
        'type' => $analysisType,
        'category' => (string) $finding['title'],
        'location' => trim((string) ($finding['file_path'] ?? '')) . (!empty($finding['line_number']) ? ':' . (int) $finding['line_number'] : ''),
        'analysis' => (string) ($finding['category'] ?? 'Audit'),
        'priority' => strtolower((string) ($finding['severity'] ?? 'info')),
        'tagged' => trim((string) ($finding['cwe_id'] ?? '')) . (!empty($finding['status']) ? ' / ' . strtoupper(str_replace('_', ' ', (string) $finding['status'])) : ''),
        'status' => (string) ($finding['status'] ?? 'open'),
        'claim_state' => (string) ($finding['claim_state'] ?? 'unclaimed'),
        'claimed_by' => (string) ($finding['claimed_by'] ?? ''),
        'claimed_at' => (string) ($finding['claimed_at'] ?? ''),
        'description' => (string) ($finding['description'] ?? ''),
        'recommendation' => (string) ($finding['recommendation'] ?? ''),
        'ai_issue_summary' => (string) ($finding['ai_issue_summary'] ?? $finding['ai_summary'] ?? ''),
        'ai_remediation' => (string) ($finding['ai_remediation'] ?? ''),
        'validation_notes' => (string) ($finding['validation_notes'] ?? ''),
        'file_path' => (string) ($finding['file_path'] ?? ''),
        'line_number' => !empty($finding['line_number']) ? (int) $finding['line_number'] : null,
    ];
}

foreach ($integrations as $integration) {
    $toolCategory = (string) ($integration['tool_category'] ?? 'automation');
    $type = match ($toolCategory) {
        'sast' => 'SAST',
        'dast' => 'DAST',
        'sca' => 'SCA',
        'mobile' => 'Mobile',
        'pentest' => 'PT',
        default => 'OASM',
    };

    $auditRows[] = [
        'kind' => 'tool',
        'id' => 0,
        'type' => $type,
        'category' => (string) $integration['name'],
        'location' => (string) ($integration['endpoint_url'] ?? 'n/a'),
        'analysis' => strtoupper((string) ($integration['connection_type'] ?? 'manual')),
        'priority' => strtolower((string) ($integration['status'] ?? 'configured')),
        'tagged' => (string) ($integration['description'] ?? ''),
        'status' => (string) ($integration['status'] ?? 'configured'),
        'claim_state' => 'n/a',
        'claimed_by' => '',
        'claimed_at' => '',
        'description' => (string) ($integration['description'] ?? ''),
        'recommendation' => 'Review tool status and endpoint health.',
        'ai_issue_summary' => '',
        'ai_remediation' => '',
        'validation_notes' => '',
        'file_path' => '',
        'line_number' => null,
    ];
}

foreach ($assets as $asset) {
    $auditRows[] = [
        'kind' => 'asset',
        'id' => 0,
        'type' => 'OASM',
        'category' => (string) $asset['asset_name'],
        'location' => (string) ($asset['asset_url'] ?? ''),
        'analysis' => strtoupper((string) ($asset['asset_type'] ?? 'asset')),
        'priority' => strtolower((string) ($asset['exposure'] ?? 'public')),
        'tagged' => strtoupper((string) ($asset['status'] ?? 'discovered')),
        'status' => (string) ($asset['status'] ?? 'discovered'),
        'claim_state' => 'n/a',
        'claimed_by' => '',
        'claimed_at' => '',
        'description' => (string) ($asset['notes'] ?? ''),
        'recommendation' => 'Keep exposure scoped and verify ownership.',
        'ai_issue_summary' => '',
        'ai_remediation' => '',
        'validation_notes' => '',
        'file_path' => '',
        'line_number' => null,
    ];
}

$counts = [
    'critical' => count(array_filter($findings, fn($f) => ($f['severity'] ?? '') === 'critical')),
    'high' => count(array_filter($findings, fn($f) => ($f['severity'] ?? '') === 'high')),
    'medium' => count(array_filter($findings, fn($f) => ($f['severity'] ?? '') === 'medium')),
    'low' => count(array_filter($findings, fn($f) => ($f['severity'] ?? '') === 'low')),
    'all' => count($auditRows),
    'sast' => count(array_filter($auditRows, fn($row) => $row['type'] === 'SAST')),
    'dast' => count(array_filter($auditRows, fn($row) => $row['type'] === 'DAST')),
    'sca' => count(array_filter($auditRows, fn($row) => $row['type'] === 'SCA')),
    'mobile' => count(array_filter($auditRows, fn($row) => $row['type'] === 'Mobile')),
    'pt' => count(array_filter($auditRows, fn($row) => $row['type'] === 'PT')),
    'oasm' => count(array_filter($auditRows, fn($row) => $row['type'] === 'OASM')),
];

$findingMap = [];
foreach ($findings as $finding) {
    $findingMap[(int) $finding['id']] = $finding;
}

$claimedCount = count(array_filter($findings, fn($f) => (string) ($f['claim_state'] ?? 'unclaimed') === 'claimed'));
$suppressedCount = count(array_filter($findings, fn($f) => (string) ($f['status'] ?? '') === 'false_positive'));
$openCount = count(array_filter($findings, fn($f) => (string) ($f['status'] ?? '') === 'open'));
$toolReady = count(array_filter($integrations, fn($tool) => (string) ($tool['status'] ?? '') === 'ready'));
$toolTotal = count($integrations);

$user = currentUser();
$role = currentUserRole();
$canManage = in_array($role, ['admin', 'manager'], true);
$canImport = in_array($role, ['admin', 'manager', 'analyst'], true);

$message = $_SESSION['audit_message'] ?? null;
$error = $_SESSION['audit_error'] ?? null;
unset($_SESSION['audit_message'], $_SESSION['audit_error']);

$selectedRow = $auditRows[0] ?? [
    'type' => '',
    'category' => '',
    'location' => '',
    'analysis' => '',
    'priority' => 'info',
    'tagged' => '',
    'status' => '',
    'claim_state' => '',
    'claimed_by' => '',
    'claimed_at' => '',
    'description' => '',
    'recommendation' => '',
    'ai_issue_summary' => '',
    'ai_remediation' => '',
    'validation_notes' => '',
    'file_path' => '',
    'line_number' => null,
];

if (!empty($_GET['finding']) && isset($findingMap[(int) $_GET['finding']])) {
    $finding = $findingMap[(int) $_GET['finding']];
    $selectedRow = [
        'kind' => 'finding',
        'id' => (int) $finding['id'],
        'type' => strtoupper((string) ($finding['category'] ?? 'SAST')),
        'category' => (string) $finding['title'],
        'location' => trim((string) ($finding['file_path'] ?? '')) . (!empty($finding['line_number']) ? ':' . (int) $finding['line_number'] : ''),
        'analysis' => (string) ($finding['category'] ?? 'Audit'),
        'priority' => strtolower((string) ($finding['severity'] ?? 'info')),
        'tagged' => trim((string) ($finding['cwe_id'] ?? '')),
        'status' => (string) ($finding['status'] ?? 'open'),
        'claim_state' => (string) ($finding['claim_state'] ?? 'unclaimed'),
        'claimed_by' => (string) ($finding['claimed_by'] ?? ''),
        'claimed_at' => (string) ($finding['claimed_at'] ?? ''),
        'description' => (string) ($finding['description'] ?? ''),
        'recommendation' => (string) ($finding['recommendation'] ?? ''),
        'ai_issue_summary' => (string) ($finding['ai_issue_summary'] ?? $finding['ai_summary'] ?? ''),
        'ai_remediation' => (string) ($finding['ai_remediation'] ?? ''),
        'validation_notes' => (string) ($finding['validation_notes'] ?? ''),
        'file_path' => (string) ($finding['file_path'] ?? ''),
        'line_number' => !empty($finding['line_number']) ? (int) $finding['line_number'] : null,
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Audit</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body class="audit-page">
  <div class="app-shell audit-shell">
    <aside class="sidebar">
      <div class="brand-lockup sidebar-brand">
        <img src="<?= e((string) ($project['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">Applications</p>
          <strong>Audit console</strong>
        </div>
      </div>
      <nav class="side-nav">
        <a class="side-link" href="home.php">Dashboard</a>
        <a class="side-link" href="scan_jobs.php">Scan jobs</a>
        <a class="side-link" href="report.php">Executive report</a>
        <a class="side-link active" href="audit.php">Audit</a>
        <a class="side-link" href="deliverables.php">Deliverables</a>
        <?php if ($canImport): ?><a class="side-link" href="import.php">Import results</a><?php endif; ?>
        <a class="side-link" href="checklist.php">Pentest checklist</a>
        <a class="side-link" href="oasm.php">Open ASM</a>
        <?php if ($canManage): ?><a class="side-link" href="clients.php">Client onboarding</a><?php endif; ?>
      </nav>
      <div class="sidebar-card">
        <span class="tag tag-okay">Live</span>
        <h3><?= e((string) ($project['name'] ?? 'Security Program')) ?></h3>
        <p><?= e((string) ($project['client_name'] ?? 'Client')) ?></p>
        <div class="sidebar-mini">
          <div><strong><?= (int) $toolReady ?></strong><span>Tools up</span></div>
          <div><strong><?= (int) $openCount ?></strong><span>Open</span></div>
          <div><strong><?= (int) $claimedCount ?></strong><span>Claimed</span></div>
        </div>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar pro-topbar">
        <div class="search-pill">
          <span class="search-icon" aria-hidden="true"></span>
          <input id="auditSearch" type="search" placeholder="Search issues, assets, or locations" aria-label="Search audit items">
        </div>
        <div class="topbar-actions">
          <span class="status-chip"><?= e(ucfirst($role)) ?></span>
          <span class="status-chip"><?= (int) $toolReady ?>/<?= (int) $toolTotal ?> tools up</span>
          <a class="button ghost" href="logout.php">Logout</a>
          <span class="user-badge"><?= e(strtoupper(substr((string) ($user['display_name'] ?? 'A'), 0, 2))) ?></span>
        </div>
      </header>

      <section class="hero-strip audit-hero">
        <div class="hero-copy">
          <p class="eyebrow">Security audit workspace</p>
          <h1>Premium review console for SAST, DAST, SCA, mobile, PT, and OASM.</h1>
          <p class="subhead">Track findings, claim reviews, suppress false positives, and keep remediation evidence in one executive-ready workspace.</p>
          <div class="hero-actions">
            <a class="button" href="report.php">Executive report</a>
            <a class="button ghost" href="deliverables.php">Deliverables</a>
          </div>
        </div>
        <div class="hero-metrics compact">
          <div><strong><?= (int) $counts['all'] ?></strong><span>Audit rows</span></div>
          <div><strong><?= (int) ($counts['critical'] + $counts['high']) ?></strong><span>Priority items</span></div>
          <div><strong><?= (int) $suppressedCount ?></strong><span>Suppressed</span></div>
          <div><strong><?= (int) $claimedCount ?></strong><span>Claimed</span></div>
        </div>
      </section>

      <section class="audit-summary">
        <div class="summary-card"><span>SAST</span><strong><?= (int) $counts['sast'] ?></strong></div>
        <div class="summary-card"><span>DAST</span><strong><?= (int) $counts['dast'] ?></strong></div>
        <div class="summary-card"><span>SCA</span><strong><?= (int) $counts['sca'] ?></strong></div>
        <div class="summary-card"><span>Mobile</span><strong><?= (int) $counts['mobile'] ?></strong></div>
        <div class="summary-card"><span>PT</span><strong><?= (int) $counts['pt'] ?></strong></div>
        <div class="summary-card"><span>OASM</span><strong><?= (int) $counts['oasm'] ?></strong></div>
      </section>

      <section class="audit-toolbar">
        <div class="audit-filter-pills">
          <button class="audit-pill active" data-filter="all">All <span><?= (int) $counts['all'] ?></span></button>
          <button class="audit-pill" data-filter="critical">Critical <span><?= (int) $counts['critical'] ?></span></button>
          <button class="audit-pill" data-filter="high">High <span><?= (int) $counts['high'] ?></span></button>
          <button class="audit-pill" data-filter="medium">Medium <span><?= (int) $counts['medium'] ?></span></button>
          <button class="audit-pill" data-filter="low">Low <span><?= (int) $counts['low'] ?></span></button>
        </div>
        <div class="audit-type-pills">
          <button class="audit-pill active" data-type="all">All</button>
          <button class="audit-pill" data-type="SAST">SAST <span><?= (int) $counts['sast'] ?></span></button>
          <button class="audit-pill" data-type="DAST">DAST <span><?= (int) $counts['dast'] ?></span></button>
          <button class="audit-pill" data-type="SCA">SCA <span><?= (int) $counts['sca'] ?></span></button>
          <button class="audit-pill" data-type="Mobile">Mobile <span><?= (int) $counts['mobile'] ?></span></button>
          <button class="audit-pill" data-type="PT">PT <span><?= (int) $counts['pt'] ?></span></button>
          <button class="audit-pill" data-type="OASM">OASM <span><?= (int) $counts['oasm'] ?></span></button>
        </div>
        <div class="audit-search-row">
          <select class="audit-select" aria-label="Group by">
            <option>Group by</option>
            <option>Category</option>
            <option>Priority</option>
            <option>Analysis Type</option>
          </select>
          <select class="audit-select" aria-label="Filter by">
            <option>Filter by</option>
            <option>Primary location</option>
            <option>Tagged</option>
            <option>Priority</option>
          </select>
          <a class="audit-clear" href="audit.php">Clear all</a>
        </div>
      </section>

      <section class="audit-workspace">
        <section class="panel wide audit-table-panel">
          <div class="panel-header">
            <h3>Audit findings</h3>
            <span class="muted">Category, primary location, analysis type, priority, and tagged evidence</span>
          </div>
          <div class="table-wrap">
            <table class="audit-table" id="auditTable">
              <thead>
                <tr>
                  <th></th>
                  <th>Category</th>
                  <th>Primary Location</th>
                  <th>Analysis Type</th>
                  <th>Priority</th>
                  <th>Tagged</th>
                  <th>Source</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($auditRows as $row): ?>
                  <tr
                    tabindex="0"
                    data-id="<?= (int) ($row['id'] ?? 0) ?>"
                    data-kind="<?= e((string) $row['kind']) ?>"
                    data-severity="<?= e((string) $row['priority']) ?>"
                    data-type="<?= e((string) $row['type']) ?>"
                    data-search="<?= e(strtolower(implode(' ', array_filter($row, fn($v) => is_scalar($v) && $v !== '')))) ?>"
                    data-title="<?= e((string) $row['category']) ?>"
                    data-location="<?= e((string) $row['location']) ?>"
                    data-analysis="<?= e((string) $row['analysis']) ?>"
                    data-priority="<?= e((string) $row['priority']) ?>"
                    data-tagged="<?= e((string) $row['tagged']) ?>"
                    data-status="<?= e((string) ($row['status'] ?? '')) ?>"
                    data-claim-state="<?= e((string) ($row['claim_state'] ?? '')) ?>"
                    data-claimed-by="<?= e((string) ($row['claimed_by'] ?? '')) ?>"
                    data-claimed-at="<?= e((string) ($row['claimed_at'] ?? '')) ?>"
                    data-description="<?= e((string) ($row['description'] ?? '')) ?>"
                    data-recommendation="<?= e((string) ($row['recommendation'] ?? '')) ?>"
                    data-ai-issue-summary="<?= e((string) ($row['ai_issue_summary'] ?? '')) ?>"
                    data-ai-remediation="<?= e((string) ($row['ai_remediation'] ?? '')) ?>"
                    data-validation-notes="<?= e((string) ($row['validation_notes'] ?? '')) ?>"
                    data-file-path="<?= e((string) ($row['file_path'] ?? '')) ?>"
                    data-line-number="<?= e((string) ($row['line_number'] ?? '')) ?>"
                  >
                    <td><input type="checkbox" aria-label="Select row"></td>
                    <td><?= e((string) $row['category']) ?></td>
                    <td><?= e((string) $row['location']) ?></td>
                    <td><?= e((string) $row['analysis']) ?></td>
                    <td><span class="audit-priority <?= e((string) $row['priority']) ?>"><?= e(strtoupper((string) $row['priority'])) ?></span></td>
                    <td><?= e((string) $row['tagged']) ?></td>
                    <td><?= e((string) $row['type']) ?></td>
                    <td>
                      <?php if (($row['kind'] ?? '') === 'finding'): ?>
                        <div class="row-actions">
                          <form method="post" class="row-action-form">
                            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                            <input type="hidden" name="finding_id" value="<?= (int) ($row['id'] ?? 0) ?>">
                            <button class="button ghost audit-mini-button" type="submit" name="action" value="claim"><?= (($row['claim_state'] ?? 'unclaimed') === 'claimed') ? 'Reclaim' : 'Claim' ?></button>
                            <button class="button ghost audit-mini-button" type="submit" name="action" value="<?= (($row['status'] ?? '') === 'false_positive') ? 'unsuppress' : 'suppress' ?>"><?= (($row['status'] ?? '') === 'false_positive') ? 'Unsuppress' : 'Suppress' ?></button>
                          </form>
                        </div>
                      <?php else: ?>
                        <span class="muted">Managed</span>
                      <?php endif; ?>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </section>
        <aside class="panel audit-detail" id="auditDetail">
          <div class="panel-header">
            <h3>Selected item</h3>
            <span class="muted">Details, remediation, and validation notes</span>
          </div>
          <div class="audit-detail-card">
            <div class="audit-detail-kicker" id="auditDetailType"><?= e((string) ($selectedRow['type'] ?? '')) ?></div>
            <h4 id="auditDetailTitle"><?= e((string) ($selectedRow['category'] ?? 'Select a row')) ?></h4>
            <p id="auditDetailLocation"><?= e((string) ($selectedRow['location'] ?? '')) ?></p>
            <div class="finding-badges">
              <span class="tag" id="auditDetailPriority"><?= e(strtoupper((string) ($selectedRow['priority'] ?? ''))) ?></span>
              <span class="tag" id="auditDetailStatus"><?= e(strtoupper(str_replace('_', ' ', (string) ($selectedRow['status'] ?? '')))) ?></span>
            </div>
            <div class="detail-stack">
              <div><span>Claim</span><strong id="auditDetailClaim"><?= e((string) ($selectedRow['claim_state'] ?? '')) ?></strong></div>
              <div><span>Claimed by</span><strong id="auditDetailClaimedBy"><?= e((string) ($selectedRow['claimed_by'] ?? '')) ?></strong></div>
              <div><span>Claimed at</span><strong id="auditDetailClaimedAt"><?= e((string) ($selectedRow['claimed_at'] ?? '')) ?></strong></div>
            </div>
            <div class="detail-block">
              <span>Description</span>
              <p id="auditDetailDescription"><?= e((string) ($selectedRow['description'] ?? '')) ?></p>
            </div>
            <div class="detail-block">
              <span>Recommendation</span>
              <p id="auditDetailRecommendation"><?= e((string) ($selectedRow['recommendation'] ?? '')) ?></p>
            </div>
            <div class="detail-block">
              <span>AI issue summary</span>
              <p id="auditDetailAiIssue"><?= e((string) ($selectedRow['ai_issue_summary'] ?? '')) ?></p>
            </div>
            <div class="detail-block">
              <span>AI remediation</span>
              <p id="auditDetailAiRemediation"><?= e((string) ($selectedRow['ai_remediation'] ?? '')) ?></p>
            </div>
            <div class="detail-block">
              <span>Validation notes</span>
              <p id="auditDetailValidation"><?= e((string) ($selectedRow['validation_notes'] ?? '')) ?></p>
            </div>
            <div class="detail-stack">
              <div><span>Tagged</span><strong id="auditDetailTagged"><?= e((string) ($selectedRow['tagged'] ?? '')) ?></strong></div>
              <div><span>Analysis</span><strong id="auditDetailAnalysis"><?= e((string) ($selectedRow['analysis'] ?? '')) ?></strong></div>
              <div><span>Source</span><strong id="auditDetailSource"><?= e((string) ($selectedRow['file_path'] ?? '')) ?></strong></div>
            </div>
          </div>
        </aside>
      </section>
    </main>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
