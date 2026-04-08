<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireRole(['admin', 'manager']);

$pdo = Database::pdo();
$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$pdo) {
        $error = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $error = 'Your session expired. Please try again.';
    } else {
        $projectId = (int) ($_POST['project_id'] ?? 0);
        $name = trim((string) ($_POST['name'] ?? ''));
        $type = (string) ($_POST['type'] ?? 'scanner');
        $status = (string) ($_POST['status'] ?? 'configured');
        $endpointUrl = trim((string) ($_POST['endpoint_url'] ?? ''));
        $description = trim((string) ($_POST['description'] ?? ''));

        if ($projectId <= 0 || $name === '') {
            $error = 'Select a project and provide an add-on name.';
        } else {
            $stmt = $pdo->prepare('INSERT INTO integrations (project_id, name, type, status, endpoint_url, description) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->execute([
                $projectId,
                $name,
                $type,
                $status,
                $endpointUrl !== '' ? $endpointUrl : null,
                $description !== '' ? $description : null,
            ]);
            $message = 'Add-on saved successfully.';
        }
    }
}

$projects = [];
$integrations = [];
if ($pdo) {
    $projects = $pdo->query('SELECT id, name, client_name FROM projects ORDER BY id DESC')->fetchAll();
    try {
        $integrations = $pdo->query('SELECT i.*, p.name AS project_name, p.client_name FROM integrations i INNER JOIN projects p ON p.id = i.project_id ORDER BY i.created_at DESC')->fetchAll();
    } catch (Throwable $e) {
        $integrations = [];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Add-ons</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
  <div class="page-shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">Add-ons</p>
        <h1>Manage MobSF and assistant integrations</h1>
        <p class="subhead">Register scanner and assistant add-ons so the dashboard knows where to route mobile security and triage workflows.</p>
      </div>
      <div class="topbar-actions">
        <a class="button ghost" href="home.php">Dashboard</a>
        <a class="button" href="report.php">Reports</a>
      </div>
    </header>

    <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>

    <section class="panel form-panel">
      <form method="post" class="import-form">
        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
        <label>
          <span>Project</span>
          <select name="project_id" required>
            <option value="">Select a project</option>
            <?php foreach ($projects ?: [['id' => 1, 'name' => 'Client Portal', 'client_name' => 'Acme Corporation']] as $project): ?>
              <option value="<?= (int) $project['id'] ?>"><?= e($project['name'] . ' - ' . $project['client_name']) ?></option>
            <?php endforeach; ?>
          </select>
        </label>
        <label>
          <span>Add-on name</span>
          <input type="text" name="name" placeholder="MobSF / OASM Assistant" required>
        </label>
        <label>
          <span>Type</span>
          <select name="type">
            <option value="scanner">Scanner</option>
            <option value="assistant">Assistant</option>
            <option value="automation">Automation</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <select name="status">
            <option value="configured">Configured</option>
            <option value="ready">Ready</option>
            <option value="disabled">Disabled</option>
          </select>
        </label>
        <label class="full">
          <span>Endpoint URL</span>
          <input type="url" name="endpoint_url" placeholder="http://mobsf:8000 or https://assistant.example.com">
        </label>
        <label class="full">
          <span>Description</span>
          <textarea name="description" rows="4" placeholder="Describe what this add-on does for the program."></textarea>
        </label>
        <div class="form-actions full">
          <button class="button" type="submit">Save add-on</button>
          <a class="button ghost" href="home.php">Cancel</a>
        </div>
      </form>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Configured add-ons</h3>
        <span class="muted">MobSF is available as a local service in Compose</span>
      </div>
      <div class="finding-list">
        <?php foreach ($integrations as $integration): ?>
          <article class="finding-card <?= e(integrationStatusClass((string) ($integration['status'] ?? 'configured'))) ?>">
            <div class="finding-head">
              <strong><?= e((string) $integration['name']) ?></strong>
              <div class="finding-badges">
                <span class="tag"><?= e(strtoupper((string) $integration['type'])) ?></span>
                <span class="tag <?= e(integrationStatusClass((string) $integration['status'])) ?>"><?= e(strtoupper((string) $integration['status'])) ?></span>
              </div>
            </div>
            <p><?= e((string) ($integration['description'] ?? '')) ?></p>
            <div class="finding-foot">
              <span><?= e((string) $integration['project_name']) ?></span>
              <span><?= e((string) ($integration['endpoint_url'] ?? 'n/a')) ?></span>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
    </section>
  </div>
</body>
</html>
