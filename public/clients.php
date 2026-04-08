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
        $name = trim((string) ($_POST['name'] ?? ''));
        $clientName = trim((string) ($_POST['client_name'] ?? ''));
        $portalUrl = trim((string) ($_POST['portal_url'] ?? ''));
        $repoUrl = trim((string) ($_POST['repository_url'] ?? ''));
        $targetUrl = trim((string) ($_POST['target_url'] ?? ''));
        $sourceUrl = trim((string) ($_POST['source_url'] ?? ''));
        $sourceUsername = trim((string) ($_POST['source_username'] ?? ''));
        $sourcePasswordHint = trim((string) ($_POST['source_password_hint'] ?? ''));
        $logoPath = 'assets/img/cyber-logo.png';

        if ($name === '' || $clientName === '') {
            $error = 'Project name and client name are required.';
        } else {
            if (!empty($_FILES['client_logo']['name']) && is_uploaded_file($_FILES['client_logo']['tmp_name'])) {
                $logoDir = __DIR__ . '/uploads/client-logos';
                if (!is_dir($logoDir)) {
                    mkdir($logoDir, 0775, true);
                }

                $extension = strtolower(pathinfo((string) $_FILES['client_logo']['name'], PATHINFO_EXTENSION));
                $allowed = ['png', 'jpg', 'jpeg', 'webp', 'gif'];
                if (!in_array($extension, $allowed, true)) {
                    $error = 'Client logo must be a PNG, JPG, GIF, or WEBP file.';
                } else {
                    $logoName = uniqid('client-logo-', true) . '.' . $extension;
                    $logoTarget = $logoDir . DIRECTORY_SEPARATOR . $logoName;
                    if (move_uploaded_file($_FILES['client_logo']['tmp_name'], $logoTarget)) {
                        $logoPath = 'uploads/client-logos/' . $logoName;
                    } else {
                        $error = 'Unable to save the uploaded client logo.';
                    }
                }
            }
        }

        if (!$error) {
            $stmt = $pdo->prepare('
                INSERT INTO projects (name, client_name, client_logo_path, portal_url, repository_url, target_url, source_url, source_username, source_password_hint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');
            $stmt->execute([
                $name,
                $clientName,
                $logoPath,
                $portalUrl !== '' ? $portalUrl : null,
                $repoUrl !== '' ? $repoUrl : null,
                $targetUrl !== '' ? $targetUrl : null,
                $sourceUrl !== '' ? $sourceUrl : null,
                $sourceUsername !== '' ? $sourceUsername : null,
                $sourcePasswordHint !== '' ? $sourcePasswordHint : null,
            ]);

            $message = 'Client onboarded successfully.';
        }
    }
}

$projects = [];
if ($pdo) {
    $stmt = $pdo->query('SELECT * FROM projects ORDER BY id DESC');
    $projects = $stmt->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Clients</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
  <div class="page-shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">Client onboarding</p>
        <h1>Bring new clients into the platform</h1>
        <p class="subhead">Capture logos, portal access, repository links, and source credentials in one controlled setup screen.</p>
      </div>
      <div class="topbar-actions">
        <a class="button ghost" href="home.php">Dashboard</a>
        <a class="button" href="report.php">Reports</a>
      </div>
    </header>

    <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>

    <section class="panel form-panel">
      <form method="post" enctype="multipart/form-data" class="import-form">
        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
        <label>
          <span>Project name</span>
          <input type="text" name="name" placeholder="Enterprise Security Review" required>
        </label>
        <label>
          <span>Client name</span>
          <input type="text" name="client_name" placeholder="Acme Corporation" required>
        </label>
        <label>
          <span>Portal URL</span>
          <input type="url" name="portal_url" placeholder="https://client.example.com">
        </label>
        <label>
          <span>Repository URL</span>
          <input type="url" name="repository_url" placeholder="https://github.com/org/repo">
        </label>
        <label>
          <span>Target URL</span>
          <input type="url" name="target_url" placeholder="https://app.example.com">
        </label>
        <label>
          <span>Source URL</span>
          <input type="url" name="source_url" placeholder="https://git.example.com/project.git">
        </label>
        <label>
          <span>Source username</span>
          <input type="text" name="source_username" placeholder="delivery@example.com">
        </label>
        <label>
          <span>Source password hint</span>
          <input type="text" name="source_password_hint" placeholder="Provided via secure channel">
        </label>
        <label class="full">
          <span>Client logo</span>
          <input type="file" name="client_logo" accept=".png,.jpg,.jpeg,.webp,.gif">
        </label>
        <div class="form-actions full">
          <button class="button" type="submit">Onboard client</button>
          <a class="button ghost" href="home.php">Cancel</a>
        </div>
      </form>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Onboarded clients</h3>
        <span class="muted">Role-based access and credential notes</span>
      </div>
      <div class="activity-list">
        <?php foreach ($projects as $project): ?>
          <div class="activity-row">
            <div class="activity-dot"></div>
            <div class="activity-main">
              <strong><?= e((string) $project['name']) ?></strong>
              <span><?= e((string) $project['client_name']) ?></span>
              <small class="muted"><?= e((string) ($project['portal_url'] ?? '')) ?></small>
            </div>
            <div class="activity-meta">
              <span class="tag"><?= e(currentUserRole()) ?></span>
              <span class="tag tag-okay">Client ready</span>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </section>
  </div>
</body>
</html>
