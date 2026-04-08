<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireRole(['admin', 'manager', 'analyst']);

$pdo = Database::pdo();
$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $source = trim((string) ($_POST['source_name'] ?? ''));
    $payload = trim((string) ($_POST['payload'] ?? ''));
    $projectId = (int) ($_POST['project_id'] ?? 0);
    $sourceMode = (string) ($_POST['source_mode'] ?? 'manual');
    $sourceDetail = trim((string) ($_POST['source_detail'] ?? ''));
    $artifactPath = null;
    $decodedPayload = [];
    $sourceKey = strtolower($source);
    $toolName = $source !== '' ? $source : 'Imported scan';
    $scanType = match (true) {
        str_contains($sourceKey, 'sonar') => 'sonarqube',
        str_contains($sourceKey, 'zap') => 'zap',
        str_contains($sourceKey, 'mobsf') || str_contains($sourceKey, 'mobile') => 'sast',
        str_contains($sourceKey, 'dependency') || str_contains($sourceKey, 'sca') => 'sca',
        default => 'sast',
    };

    if (!$pdo) {
        $error = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif ($projectId <= 0 || $source === '' || $payload === '') {
        $error = 'Please provide a project, source, and payload.';
    } else {
        $decodedPayload = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $error = 'Payload must be valid JSON so it can be stored in MySQL.';
        } elseif ($sourceMode === 'upload') {
            if (empty($_FILES['source_archive']['name']) || !is_uploaded_file($_FILES['source_archive']['tmp_name'])) {
                $error = 'Please upload a source archive or choose URL mode.';
            } else {
                $uploadDir = __DIR__ . '/../storage/source-uploads';
                if (!is_dir($uploadDir)) {
                    mkdir($uploadDir, 0775, true);
                }

                $extension = strtolower(pathinfo((string) $_FILES['source_archive']['name'], PATHINFO_EXTENSION));
                $allowed = ['zip', 'tar', 'gz', 'tgz'];
                if (!in_array($extension, $allowed, true)) {
                    $error = 'Source archive must be ZIP, TAR, GZ, or TGZ.';
                } else {
                    $archiveName = uniqid('source-', true) . '.' . $extension;
                    $archiveTarget = $uploadDir . DIRECTORY_SEPARATOR . $archiveName;
                    if (move_uploaded_file($_FILES['source_archive']['tmp_name'], $archiveTarget)) {
                        $artifactPath = 'storage/source-uploads/' . $archiveName;
                    } else {
                        $error = 'Unable to save the uploaded source archive.';
                    }
                }
            }
        } elseif ($sourceMode === 'url' && $sourceDetail === '') {
            $error = 'Please provide a source URL for URL-based imports.';
        }
    }

        if (!$error && $pdo && $projectId > 0) {
            $stmt = $pdo->prepare('INSERT INTO imports (project_id, source_type, source_name, source_detail, artifact_path, file_name) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->execute([
                $projectId,
                $sourceMode,
                $source,
                $sourceDetail !== '' ? $sourceDetail : null,
                $artifactPath,
                $artifactPath ? basename($artifactPath) : 'manual-import.json',
            ]);

            if (is_array($decodedPayload) && !empty($decodedPayload['tool_name'])) {
                $toolName = trim((string) $decodedPayload['tool_name']);
            } elseif (is_array($decodedPayload) && !empty($decodedPayload['tool'])) {
                $toolName = trim((string) $decodedPayload['tool']);
            } elseif (is_array($decodedPayload) && !empty($decodedPayload['scan_type'])) {
                $scanType = strtolower(trim((string) $decodedPayload['scan_type']));
            }

            if (!in_array($scanType, ['sast', 'dast', 'sca', 'sonarqube', 'zap'], true)) {
                $scanType = 'sast';
            }

            $scanStmt = $pdo->prepare('INSERT INTO scan_runs (project_id, scan_type, tool_name, status, summary, raw_payload) VALUES (?, ?, ?, ?, ?, ?)');
            $scanStmt->execute([
                $projectId,
                $scanType,
                $toolName . ($artifactPath ? ' (uploaded archive)' : ''),
                'completed',
                $sourceMode === 'upload'
                    ? 'Imported security results from an uploaded source archive.'
                    : ($sourceMode === 'url'
                        ? 'Imported security results from a source URL.'
                        : 'Imported security results from the client workflow.'),
                json_encode($decodedPayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ]);

            $scanRunId = (int) $pdo->lastInsertId();
            $findingCount = 0;
            if (is_array($decodedPayload)) {
                $findingCount = ingestImportedFindings($pdo, $scanRunId, $source, $toolName, $scanType, $decodedPayload);
            }

            if ($findingCount > 0) {
                $summaryStmt = $pdo->prepare('UPDATE scan_runs SET summary = ? WHERE id = ?');
                $summaryStmt->execute([
                    sprintf(
                        'Imported %d finding%s from %s. AI issue summaries, remediation, and validation notes were auto-populated.',
                        $findingCount,
                        $findingCount === 1 ? '' : 's',
                        $toolName
                    ),
                    $scanRunId,
                ]);
            }

            $message = $findingCount > 0
                ? 'Import stored successfully and findings were normalized into the report.'
                : 'Import stored successfully. The report pages can now reflect the new run.';
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
        <p class="subhead">Supported imports: SonarQube, OWASP ZAP, MobSF, dependency-check, and other normalized JSON feeds. AI summaries and remediation notes are auto-filled when possible.</p>
      </div>
      <div class="topbar-actions">
        <a class="button ghost" href="home.php">Dashboard</a>
        <a class="button" href="report.php">Report</a>
      </div>
    </header>

    <section class="panel form-panel">
      <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
      <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>

      <form method="post" enctype="multipart/form-data" class="import-form">
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
          <span>Import mode</span>
          <select name="source_mode">
            <option value="manual">Manual JSON</option>
            <option value="url">Source URL</option>
            <option value="upload">Archive upload</option>
          </select>
        </label>
        <label>
          <span>Source name</span>
          <input type="text" name="source_name" placeholder="SonarQube / OWASP ZAP / Dependency-Check" required>
        </label>
        <label>
          <span>Source reference URL</span>
          <input type="url" name="source_detail" placeholder="https://github.com/org/repo or tool endpoint">
        </label>
        <label class="full">
          <span>Upload source archive</span>
          <input type="file" name="source_archive" accept=".zip,.tar,.gz,.tgz">
        </label>
        <label class="full">
          <span>Payload JSON</span>
          <textarea name="payload" rows="12" placeholder='{"issues":[{"title":"Example finding","severity":"high","description":"..." }]}' required></textarea>
        </label>
        <div class="form-actions full">
          <button class="button" type="submit">Save import</button>
          <a class="button ghost" href="home.php">Cancel</a>
        </div>
      </form>
    </section>
  </div>
  <script src="assets/js/app.js"></script>
</body>
</html>
