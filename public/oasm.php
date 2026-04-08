<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();
$canManage = in_array(currentUserRole(), ['admin', 'manager'], true);
$message = null;
$error = null;
$editAssetId = (int) ($_GET['edit'] ?? 0);
$editingAsset = null;
$history = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $canManage) {
    if (!$pdo) {
        $error = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $error = 'Your session expired. Please try again.';
    } else {
        $action = (string) ($_POST['action'] ?? 'save');
        $assetId = (int) ($_POST['asset_id'] ?? 0);
        $projectId = (int) ($_POST['project_id'] ?? 0);
        $assetType = (string) ($_POST['asset_type'] ?? 'url');
        $assetName = trim((string) ($_POST['asset_name'] ?? ''));
        $assetUrl = trim((string) ($_POST['asset_url'] ?? ''));
        $exposure = (string) ($_POST['exposure'] ?? 'public');
        $status = (string) ($_POST['status'] ?? 'discovered');
        $notes = trim((string) ($_POST['notes'] ?? ''));
        $feedUrl = trim((string) ($_POST['feed_url'] ?? ''));
        $jsonPayload = trim((string) ($_POST['json_payload'] ?? ''));

        if ($action === 'import') {
            if ($projectId <= 0 || $jsonPayload === '') {
                $error = 'Select a project and provide a JSON payload to import.';
            } else {
                $records = parseOasmAssetPayload($jsonPayload);
                if (!$records) {
                    $error = 'JSON payload did not contain any asset records.';
                } else {
                    $imported = 0;
                    foreach ($records as $record) {
                        $stmt = $pdo->prepare('INSERT INTO attack_surface_assets (project_id, asset_type, asset_name, asset_url, exposure, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?)');
                        $stmt->execute([
                            $projectId,
                            $record['asset_type'],
                            $record['asset_name'],
                            $record['asset_url'] !== '' ? $record['asset_url'] : null,
                            $record['exposure'],
                            $record['status'],
                            trim(($record['notes'] ?? '') . ($feedUrl !== '' ? ' Feed: ' . $feedUrl : '')),
                        ]);
                        logOasmHistory(
                            $pdo,
                            $projectId,
                            (int) $pdo->lastInsertId(),
                            'imported',
                            'Imported via JSON bulk upload' . ($feedUrl !== '' ? ' from ' . $feedUrl : '') . '.'
                        );
                        $imported++;
                    }
                    $message = sprintf('Imported %d OASM asset%s.', $imported, $imported === 1 ? '' : 's');
                }
            }
        } elseif ($action === 'delete') {
            if ($assetId <= 0) {
                $error = 'Invalid asset selected.';
            } else {
                $assetLookup = $pdo->prepare('SELECT * FROM attack_surface_assets WHERE id = ? LIMIT 1');
                $assetLookup->execute([$assetId]);
                $assetRow = $assetLookup->fetch() ?: null;
                $deleteStmt = $pdo->prepare('DELETE FROM attack_surface_assets WHERE id = ?');
                $deleteStmt->execute([$assetId]);
                if ($assetRow) {
                    logOasmHistory($pdo, (int) $assetRow['project_id'], (int) $assetRow['id'], 'deleted', 'Asset removed from OASM.');
                }
                $message = 'Asset removed from OASM.';
            }
        } else {
            if ($projectId <= 0 || $assetName === '') {
                $error = 'Project and asset name are required.';
            } elseif ($assetId > 0) {
                $stmt = $pdo->prepare('UPDATE attack_surface_assets SET project_id = ?, asset_type = ?, asset_name = ?, asset_url = ?, exposure = ?, status = ?, notes = ? WHERE id = ?');
                $stmt->execute([
                    $projectId,
                    $assetType,
                    $assetName,
                    $assetUrl !== '' ? $assetUrl : null,
                    $exposure,
                    $status,
                    $notes !== '' ? $notes : null,
                    $assetId,
                ]);
                logOasmHistory($pdo, $projectId, $assetId, 'updated', 'Asset metadata updated through the GUI.');
                $message = 'Asset updated in OASM.';
            } else {
                $stmt = $pdo->prepare('INSERT INTO attack_surface_assets (project_id, asset_type, asset_name, asset_url, exposure, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?)');
                $stmt->execute([
                    $projectId,
                    $assetType,
                    $assetName,
                    $assetUrl !== '' ? $assetUrl : null,
                    $exposure,
                    $status,
                    $notes !== '' ? $notes : null,
                ]);
                logOasmHistory($pdo, $projectId, (int) $pdo->lastInsertId(), 'created', 'Asset added through the GUI.');
                $message = 'Asset saved to OASM.';
            }
        }
    }
}

$tabs = [
    ['label' => 'Pentest checklist', 'href' => 'checklist.php', 'active' => false],
    ['label' => 'Open ASM', 'href' => 'oasm.php', 'active' => true],
];

$projects = [];
$assets = oasmAssetSamples();
if ($pdo) {
    $projects = $pdo->query('SELECT id, name, client_name FROM projects ORDER BY id DESC')->fetchAll();
    $assetStmt = $pdo->query('SELECT * FROM attack_surface_assets ORDER BY created_at DESC');
    $dbAssets = $assetStmt ? $assetStmt->fetchAll() : [];
    if ($dbAssets) {
        $assets = $dbAssets;
    }
    $historyStmt = $pdo->query('SELECT * FROM attack_surface_history ORDER BY created_at DESC LIMIT 25');
    $history = $historyStmt ? $historyStmt->fetchAll() : [];
    if ($editAssetId > 0) {
        $editStmt = $pdo->prepare('SELECT * FROM attack_surface_assets WHERE id = ? LIMIT 1');
        $editStmt->execute([$editAssetId]);
        $editingAsset = $editStmt->fetch() ?: null;
    }
}
$integrations = sampleDashboard()['integrations'];
$oasmIntegration = null;
foreach ($integrations as $integration) {
    if (($integration['name'] ?? '') === 'Open Attack Surface Management') {
        $oasmIntegration = $integration;
        break;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Open ASM</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
  <div class="page-shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">Open Attack Surface Management</p>
        <h1>Track exposed assets with executive clarity</h1>
        <p class="subhead">Manage public, internal, and restricted assets while keeping the report aligned with authorized exposure review.</p>
      </div>
      <div class="topbar-actions">
        <a class="button ghost" href="home.php">Dashboard</a>
        <a class="button" href="checklist.php">Pentest checklist</a>
        <a class="button ghost" href="audit.php">Audit</a>
      </div>
    </header>

    <div class="tab-strip">
      <?php foreach ($tabs as $tab): ?>
        <a class="tab-link <?= $tab['active'] ? 'active' : '' ?>" href="<?= e($tab['href']) ?>"><?= e($tab['label']) ?></a>
      <?php endforeach; ?>
    </div>

    <?php if ($message): ?><div class="notice success"><?= e((string) $message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="notice danger"><?= e((string) $error) ?></div><?php endif; ?>

    <?php if ($canManage): ?>
      <section class="panel form-panel">
        <form method="post" class="import-form">
          <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
          <input type="hidden" name="asset_id" value="<?= (int) ($editingAsset['id'] ?? 0) ?>">
          <input type="hidden" name="action" value="<?= $editingAsset ? 'update' : 'save' ?>">
          <label>
            <span>Project</span>
            <select name="project_id" required>
              <option value="">Select a project</option>
              <?php foreach ($projects ?: [['id' => 1, 'name' => 'Client Portal', 'client_name' => 'Acme Corporation']] as $project): ?>
                <option value="<?= (int) $project['id'] ?>" <?= (int) ($editingAsset['project_id'] ?? 0) === (int) $project['id'] ? 'selected' : '' ?>><?= e($project['name'] . ' - ' . $project['client_name']) ?></option>
              <?php endforeach; ?>
            </select>
          </label>
          <label>
            <span>Asset type</span>
            <select name="asset_type">
              <?php foreach (['domain' => 'Domain', 'subdomain' => 'Subdomain', 'ip' => 'IP', 'url' => 'URL', 'api' => 'API', 'mobile' => 'Mobile', 'repo' => 'Repository'] as $value => $label): ?>
                <option value="<?= e($value) ?>" <?= (($editingAsset['asset_type'] ?? 'url') === $value) ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
          </label>
          <label>
            <span>Exposure</span>
            <select name="exposure">
              <?php foreach (['public' => 'Public', 'internal' => 'Internal', 'restricted' => 'Restricted'] as $value => $label): ?>
                <option value="<?= e($value) ?>" <?= (($editingAsset['exposure'] ?? 'public') === $value) ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
          </label>
          <label>
            <span>Status</span>
            <select name="status">
              <?php foreach (['discovered' => 'Discovered', 'reviewed' => 'Reviewed', 'in_scope' => 'In scope', 'out_of_scope' => 'Out of scope'] as $value => $label): ?>
                <option value="<?= e($value) ?>" <?= (($editingAsset['status'] ?? 'discovered') === $value) ? 'selected' : '' ?>><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
          </label>
          <label class="full">
            <span>Asset name</span>
            <input type="text" name="asset_name" placeholder="api.client.example.com" value="<?= e((string) ($editingAsset['asset_name'] ?? '')) ?>" required>
          </label>
          <label class="full">
            <span>Asset URL</span>
            <input type="url" name="asset_url" placeholder="https://api.client.example.com" value="<?= e((string) ($editingAsset['asset_url'] ?? '')) ?>">
          </label>
          <label class="full">
            <span>Notes</span>
            <textarea name="notes" rows="3" placeholder="Exposure notes, validation context, or ownership"><?= e((string) ($editingAsset['notes'] ?? '')) ?></textarea>
          </label>
          <div class="form-actions full">
            <button class="button" type="submit"><?= $editingAsset ? 'Update asset' : 'Save asset' ?></button>
            <?php if ($editingAsset): ?><a class="button ghost" href="oasm.php">Cancel edit</a><?php endif; ?>
          </div>
        </form>
      </section>

      <section class="panel form-panel">
        <form method="post" class="import-form">
          <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
          <input type="hidden" name="action" value="import">
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
            <span>API feed URL</span>
            <input type="url" name="feed_url" placeholder="https://oasm.example.local/assets or internal feed endpoint">
          </label>
          <label class="full">
            <span>JSON payload</span>
            <textarea name="json_payload" rows="6" placeholder='{"assets":[{"asset_type":"domain","asset_name":"client.example.com","asset_url":"https://client.example.com","exposure":"public","status":"reviewed","notes":"Primary portal"}]}'></textarea>
          </label>
          <div class="form-actions full">
            <button class="button" type="submit">Import assets</button>
          </div>
        </form>
      </section>
    <?php endif; ?>

    <section class="panel">
      <div class="panel-header">
        <h3>OASM service</h3>
        <span class="muted">Linked to the Python API and registered as an add-on</span>
      </div>
      <div class="access-grid">
        <div><span>Status</span><strong><?= e((string) ($oasmIntegration['status'] ?? 'ready')) ?></strong></div>
        <div><span>Endpoint</span><strong><?= e((string) ($oasmIntegration['endpoint_url'] ?? 'http://localhost:6200')) ?></strong></div>
        <div><span>Connection</span><strong><?= e((string) ($oasmIntegration['connection_type'] ?? 'api')) ?></strong></div>
        <div><span>Category</span><strong><?= e(toolCategoryLabel((string) ($oasmIntegration['tool_category'] ?? 'assistant'))) ?></strong></div>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Asset inventory</h3>
        <span class="muted">A clean view of domain, API, subdomain, and repository exposure</span>
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
            <?php if ($canManage && isset($asset['id'])): ?>
              <div class="review-actions" style="margin-top: 12px; justify-content: flex-start;">
                <a class="button ghost" href="oasm.php?edit=<?= (int) $asset['id'] ?>">Edit</a>
                <form method="post" onsubmit="return confirm('Delete this asset from OASM?');">
                  <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                  <input type="hidden" name="action" value="delete">
                  <input type="hidden" name="asset_id" value="<?= (int) $asset['id'] ?>">
                  <button class="button ghost" type="submit">Delete</button>
                </form>
              </div>
            <?php endif; ?>
          </article>
        <?php endforeach; ?>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h3>Exposure management</h3>
        <span class="muted">Keep the asset list accurate and the scope controlled</span>
      </div>
      <div class="access-grid">
        <div><span>Public assets</span><strong>Track internet-facing domains and APIs</strong></div>
        <div><span>Internal assets</span><strong>Review what is reachable from trusted networks</strong></div>
        <div><span>Restricted assets</span><strong>Keep sensitive systems recorded but tightly controlled</strong></div>
        <div><span>Action</span><strong>Retest after every exposure change</strong></div>
      </div>
    </section>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Asset history</h3>
        <span class="muted">Audited create, update, delete, and bulk import events</span>
      </div>
      <div class="activity-list">
        <?php foreach ($history ?: [['action' => 'imported', 'actor' => 'system', 'details' => 'Seeded attack surface inventory.', 'created_at' => date('Y-m-d H:i:s')]] as $entry): ?>
          <div class="activity-row">
            <div class="activity-dot"></div>
            <div class="activity-main">
              <strong><?= e(strtoupper((string) $entry['action'])) ?></strong>
              <span><?= e((string) ($entry['details'] ?? '')) ?></span>
            </div>
            <div class="activity-meta">
              <span class="tag"><?= e((string) ($entry['actor'] ?? 'system')) ?></span>
              <small><?= e((string) ($entry['created_at'] ?? '')) ?></small>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </section>
  </div>
</body>
</html>
