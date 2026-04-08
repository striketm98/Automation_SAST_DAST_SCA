<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();
$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $source = trim((string) ($_POST['source_name'] ?? ''));
    $payload = trim((string) ($_POST['payload'] ?? ''));
    $projectId = (int) ($_POST['project_id'] ?? 0);

    if (!$pdo) {
        $error = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif ($projectId <= 0 || $source === '' || $payload === '') {
        $error = 'Please provide a project, source, and payload.';
    } else {
        $decodedPayload = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $error = 'Payload must be valid JSON so it can be stored in MySQL.';
        }
    }

    if (!$error && $pdo && $projectId > 0) {
        $stmt = $pdo->prepare('INSERT INTO imports (project_id, source_name, file_name) VALUES (?, ?, ?)');
        $stmt->execute([$projectId, $source, 'manual-import.json']);

        $scanStmt = $pdo->prepare('INSERT INTO scan_runs (project_id, scan_type, tool_name, status, summary, raw_payload) VALUES (?, ?, ?, ?, ?, ?)');
        $scanType = match (strtolower($source)) {
            'sonarqube' => 'sonarqube',
            'owasp zap', 'zap' => 'zap',
            'dependency-check', 'sca' => 'sca',
            default => 'sast',
        };
        $scanStmt->execute([
            $projectId,
            $scanType,
            $source,
            'completed',
            'Imported security results from the client workflow.',
            json_encode($decodedPayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]);

        $message = 'Import stored successfully. The report pages can now reflect the new run.';
    }
}

$projects = [];
if ($pdo) {
    $projects = $pdo->query('SELECT id, name, client_name FROM projects ORDER BY id DESC')->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Import</title>
  <link rel="icon" href="assets/img/favicon.ico">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
  <div class="page-shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">cyber-Security import</p>
        <h1>Import scan results with confidence</h1>
        <p class="subhead">Paste normalized JSON from SonarQube, ZAP, dependency-check, or your internal SAST tooling to keep every finding in one governed record.</p>
      </div>
      <div class="topbar-actions">
        <a class="button ghost" href="index.php">Dashboard</a>
        <a class="button" href="report.php">Report</a>
      </div>
    </header>

    <section class="panel form-panel">
      <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
      <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>

      <form method="post" class="import-form">
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
          <span>Source name</span>
          <input type="text" name="source_name" placeholder="SonarQube / OWASP ZAP / Dependency-Check" required>
        </label>
        <label class="full">
          <span>Payload JSON</span>
          <textarea name="payload" rows="12" placeholder='{"summary":"Import your normalized scan payload here"}' required></textarea>
        </label>
        <div class="form-actions full">
          <button class="button" type="submit">Save import</button>
          <a class="button ghost" href="index.php">Cancel</a>
        </div>
      </form>
    </section>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
