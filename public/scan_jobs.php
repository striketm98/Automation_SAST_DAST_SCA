<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireRole(['admin', 'manager', 'analyst']);

$pdo = Database::pdo();
$project = null;
$jobs = [];
$integrations = [];
$message = null;
$error = null;
$user = currentUser();
$role = currentUserRole();
$canManage = in_array($role, ['admin', 'manager'], true);

if ($pdo) {
    $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$pdo || !$project) {
        $_SESSION['scan_jobs_error'] = 'Project or database is unavailable.';
        header('Location: scan_jobs.php');
        exit;
    }
    if (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $_SESSION['scan_jobs_error'] = 'Session expired. Please try again.';
        header('Location: scan_jobs.php');
        exit;
    }

    $action = (string) ($_POST['action'] ?? '');
    $jobId = (int) ($_POST['job_id'] ?? 0);
    if ($jobId <= 0 || !in_array($action, ['retry', 'complete', 'fail'], true)) {
        $_SESSION['scan_jobs_error'] = 'Invalid scan job action.';
        header('Location: scan_jobs.php');
        exit;
    }

    try {
        $jobStmt = $pdo->prepare('SELECT * FROM scan_jobs WHERE id = ? AND project_id = ? LIMIT 1');
        $jobStmt->execute([$jobId, (int) $project['id']]);
        $job = $jobStmt->fetch() ?: null;
        if (!$job) {
            $_SESSION['scan_jobs_error'] = 'Scan job not found.';
            header('Location: scan_jobs.php');
            exit;
        }

        if ($action === 'complete') {
            $pdo->prepare('UPDATE scan_jobs SET status = ?, error_message = NULL WHERE id = ?')->execute(['completed', $jobId]);
            $pdo->prepare('UPDATE scan_runs SET status = ?, completed_at = NOW() WHERE id = ?')->execute(['completed', (int) $job['scan_run_id']]);
            $_SESSION['scan_jobs_message'] = 'Scan job marked as completed.';
            header('Location: scan_jobs.php');
            exit;
        }

        if ($action === 'fail') {
            $pdo->prepare('UPDATE scan_jobs SET status = ?, error_message = ? WHERE id = ?')->execute(['failed', 'Marked as failed by analyst action.', $jobId]);
            $pdo->prepare('UPDATE scan_runs SET status = ?, completed_at = NOW() WHERE id = ?')->execute(['failed', (int) $job['scan_run_id']]);
            $_SESSION['scan_jobs_message'] = 'Scan job marked as failed.';
            header('Location: scan_jobs.php');
            exit;
        }

        $integrationStmt = $pdo->prepare('SELECT * FROM integrations WHERE project_id = ? ORDER BY created_at DESC');
        $integrationStmt->execute([(int) $project['id']]);
        $integrations = $integrationStmt->fetchAll() ?: [];

        $retryResult = triggerScanFromUi(
            $pdo,
            (int) $project['id'],
            (string) ($job['scan_kind'] ?? 'sast'),
            (string) ($job['target_url'] ?? ''),
            (string) ($job['source_url'] ?? ''),
            $integrations
        );

        $pdo->prepare('UPDATE scan_jobs SET status = ?, error_message = ? WHERE id = ?')
            ->execute(['failed', 'Retried from UI. See newer job entry.', $jobId]);

        $_SESSION['scan_jobs_message'] = (string) ($retryResult['message'] ?? 'Scan job retried.');
        header('Location: scan_jobs.php');
        exit;
    } catch (Throwable $e) {
        $_SESSION['scan_jobs_error'] = 'Could not process scan job action right now.';
        header('Location: scan_jobs.php');
        exit;
    }
}

$message = $_SESSION['scan_jobs_message'] ?? null;
$error = $_SESSION['scan_jobs_error'] ?? null;
unset($_SESSION['scan_jobs_message'], $_SESSION['scan_jobs_error']);

if (!$project) {
    $project = sampleDashboard()['project'];
}

if ($pdo && !empty($project['id'])) {
    try {
        $jobListStmt = $pdo->prepare('
            SELECT j.*, r.tool_name, r.scan_type, r.status AS run_status, r.created_at AS run_created_at, r.completed_at,
                   i.name AS integration_name
            FROM scan_jobs j
            LEFT JOIN scan_runs r ON r.id = j.scan_run_id
            LEFT JOIN integrations i ON i.id = j.integration_id
            WHERE j.project_id = ?
            ORDER BY j.created_at DESC
            LIMIT 200
        ');
        $jobListStmt->execute([(int) $project['id']]);
        $jobs = $jobListStmt->fetchAll() ?: [];
    } catch (Throwable $e) {
        $jobs = [];
        if (!$error) {
            $error = 'Scan jobs table is initializing. Refresh in a few seconds.';
        }
    }
}

$statusCount = [
    'queued' => count(array_filter($jobs, fn($row) => (string) ($row['status'] ?? '') === 'queued')),
    'submitted' => count(array_filter($jobs, fn($row) => (string) ($row['status'] ?? '') === 'submitted')),
    'running' => count(array_filter($jobs, fn($row) => (string) ($row['status'] ?? '') === 'running')),
    'completed' => count(array_filter($jobs, fn($row) => (string) ($row['status'] ?? '') === 'completed')),
    'failed' => count(array_filter($jobs, fn($row) => (string) ($row['status'] ?? '') === 'failed')),
];

$scanKindLabel = static function (string $kind): string {
    return match (strtolower($kind)) {
        'sast' => 'SAST',
        'sca' => 'SCA',
        'dast' => 'DAST',
        'mobile' => 'Mobile APK',
        default => strtoupper($kind),
    };
};

$statusClass = static function (string $status): string {
    return match (strtolower($status)) {
        'completed' => 'tag-resolved',
        'failed' => 'tag-risk',
        'running', 'submitted' => 'tag-open',
        default => 'tag-false-positive',
    };
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Scan Jobs</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body class="audit-page">
  <div class="app-shell audit-shell">
    <aside class="sidebar">
      <div class="brand-lockup sidebar-brand">
        <img src="<?= e((string) ($project['client_logo_path'] ?? 'assets/img/cyber-logo.png')) ?>" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">Operations</p>
          <strong>Scan jobs</strong>
        </div>
      </div>
      <nav class="side-nav">
        <a class="side-link" href="home.php">Dashboard</a>
        <a class="side-link active" href="scan_jobs.php">Scan jobs</a>
        <a class="side-link" href="report.php">Executive report</a>
        <a class="side-link" href="audit.php">Audit</a>
        <a class="side-link" href="deliverables.php">Deliverables</a>
        <a class="side-link" href="import.php">Import results</a>
        <a class="side-link" href="checklist.php">Pentest checklist</a>
        <a class="side-link" href="oasm.php">Open ASM</a>
        <?php if ($canManage): ?><a class="side-link" href="addons.php">Add-ons</a><?php endif; ?>
      </nav>
      <div class="sidebar-card">
        <span class="tag tag-okay">Live queue</span>
        <h3><?= e((string) ($project['name'] ?? 'Security Program')) ?></h3>
        <p><?= e((string) ($project['client_name'] ?? 'Client')) ?></p>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar pro-topbar">
        <div class="search-pill">
          <span class="search-icon" aria-hidden="true"></span>
          <input type="text" placeholder="Scan job queue is live" aria-label="Scan jobs">
        </div>
        <div class="topbar-actions">
          <span class="status-chip"><?= e(ucfirst($role)) ?></span>
          <a class="button ghost" href="home.php">Back to dashboard</a>
          <a class="button" href="import.php">Import results</a>
          <span class="user-badge"><?= e(strtoupper(substr((string) ($user['display_name'] ?? 'A'), 0, 2))) ?></span>
        </div>
      </header>

      <section class="hero-strip audit-hero">
        <div class="hero-copy">
          <p class="eyebrow">Execution center</p>
          <h1>Track and control SAST, SCA, DAST, and APK scan jobs.</h1>
          <p class="subhead">Monitor queue health, retry connector submissions, and close scan jobs with one click.</p>
        </div>
        <div class="hero-metrics compact">
          <div><strong><?= (int) count($jobs) ?></strong><span>Total jobs</span></div>
          <div><strong><?= (int) $statusCount['queued'] ?></strong><span>Queued</span></div>
          <div><strong><?= (int) $statusCount['running'] ?></strong><span>Running</span></div>
          <div><strong><?= (int) $statusCount['failed'] ?></strong><span>Failed</span></div>
        </div>
      </section>

      <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
      <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>

      <section class="panel">
        <div class="panel-header">
          <h3>Scan job queue</h3>
          <span class="muted">Latest 200 jobs</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>Kind</th>
                <th>Tool</th>
                <th>Status</th>
                <th>Target</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($jobs as $job): ?>
                <tr>
                  <td>#<?= (int) $job['id'] ?></td>
                  <td><span class="tag"><?= e($scanKindLabel((string) ($job['scan_kind'] ?? ''))) ?></span></td>
                  <td><?= e((string) ($job['integration_name'] ?? $job['tool_name'] ?? 'Connector')) ?></td>
                  <td><span class="tag <?= e($statusClass((string) ($job['status'] ?? 'queued'))) ?>"><?= e(strtoupper((string) ($job['status'] ?? 'queued'))) ?></span></td>
                  <td><?= e((string) ($job['target_url'] ?: 'n/a')) ?></td>
                  <td><?= e((string) ($job['created_at'] ?? '-')) ?></td>
                  <td>
                    <div class="scan-job-actions">
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                        <input type="hidden" name="job_id" value="<?= (int) $job['id'] ?>">
                        <button class="button ghost audit-mini-button" type="submit" name="action" value="retry">Retry</button>
                      </form>
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                        <input type="hidden" name="job_id" value="<?= (int) $job['id'] ?>">
                        <button class="button ghost audit-mini-button" type="submit" name="action" value="complete">Mark completed</button>
                      </form>
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                        <input type="hidden" name="job_id" value="<?= (int) $job['id'] ?>">
                        <button class="button ghost audit-mini-button" type="submit" name="action" value="fail">Mark failed</button>
                      </form>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
              <?php if (!$jobs): ?>
                <tr>
                  <td colspan="7">No scan jobs yet. Launch a scan from dashboard to populate this queue.</td>
                </tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </section>
    </main>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
