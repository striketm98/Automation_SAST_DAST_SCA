<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireRole(['admin', 'manager']);

$pdo = Database::pdo();
$message = null;
$error = null;

$connectorPresets = [
    'custom' => [
        'label' => 'Custom paid tool',
        'vendor_name' => '',
        'integration_profile' => 'custom-paid-tool',
        'type' => 'scanner',
        'tool_category' => 'automation',
        'connection_type' => 'api',
        'status' => 'configured',
        'endpoint_url' => '',
        'api_base_url' => '',
        'scan_submit_url' => '',
        'result_url' => '',
        'auth_type' => 'token',
        'documentation_url' => '',
        'description' => 'Generic enterprise connector for commercial scanners with API-driven submissions and result retrieval.',
    ],
    'webinspect' => [
        'label' => 'WebInspect',
        'vendor_name' => 'OpenText',
        'integration_profile' => 'webinspect',
        'type' => 'scanner',
        'tool_category' => 'dast',
        'connection_type' => 'api',
        'status' => 'configured',
        'endpoint_url' => 'https://webinspect.example.local',
        'api_base_url' => 'https://webinspect.example.local',
        'scan_submit_url' => '/api/scan',
        'result_url' => '/api/report',
        'auth_type' => 'token',
        'documentation_url' => 'https://www.opentext.com/products/webinspect',
        'description' => 'Commercial DAST connector for authenticated scans, job submission, and result synchronization.',
    ],
    'veracode' => [
        'label' => 'Veracode',
        'vendor_name' => 'Veracode',
        'integration_profile' => 'veracode',
        'type' => 'scanner',
        'tool_category' => 'sast',
        'connection_type' => 'api',
        'status' => 'configured',
        'endpoint_url' => 'https://analysiscenter.veracode.com',
        'api_base_url' => 'https://api.veracode.com',
        'scan_submit_url' => '/appsec/v1/applications',
        'result_url' => '/appsec/v2/findings',
        'auth_type' => 'oauth2',
        'documentation_url' => 'https://docs.veracode.com/',
        'description' => 'Enterprise SAST connector for application inventory, scan orchestration, and finding import.',
    ],
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($pdo instanceof PDO) && (string) ($_POST['action'] ?? '') === 'test_connection') {
    if (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $error = 'Your session expired. Please try again.';
    } else {
        $integrationId = (int) ($_POST['integration_id'] ?? 0);
        if ($integrationId <= 0) {
            $error = 'Invalid connector selected for testing.';
        } else {
            $stmt = $pdo->prepare('SELECT * FROM integrations WHERE id = ?');
            $stmt->execute([$integrationId]);
            $integration = $stmt->fetch() ?: null;
            if (!$integration) {
                $error = 'Connector not found.';
            } else {
                $endpoint = trim((string) ($integration['endpoint_url'] ?? ''));
                $base = trim((string) ($integration['api_base_url'] ?? ''));
                $testUrl = $endpoint !== '' ? $endpoint : $base;
                $health = toolHealth($testUrl);
                $update = $pdo->prepare('UPDATE integrations SET last_tested_at = NOW(), last_test_status = ?, last_test_detail = ? WHERE id = ?');
                $update->execute([
                    (string) ($health['status'] ?? 'unknown'),
                    (string) ($health['detail'] ?? $testUrl),
                    $integrationId,
                ]);
                $message = sprintf(
                    'Connection test completed for %s: %s.',
                    (string) $integration['name'],
                    strtoupper((string) ($health['label'] ?? 'Unknown'))
                );
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string) ($_POST['action'] ?? '') !== 'test_connection') {
    if (!$pdo) {
        $error = 'Database is unavailable. Start MySQL through Docker Compose first.';
    } elseif (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
        $error = 'Your session expired. Please try again.';
    } else {
        $projectId = (int) ($_POST['project_id'] ?? 0);
        $name = trim((string) ($_POST['name'] ?? ''));
        $vendorName = trim((string) ($_POST['vendor_name'] ?? ''));
        $integrationProfile = trim((string) ($_POST['integration_profile'] ?? 'custom-paid-tool'));
        $type = (string) ($_POST['type'] ?? 'scanner');
        $toolCategory = (string) ($_POST['tool_category'] ?? 'automation');
        $connectionType = (string) ($_POST['connection_type'] ?? 'manual');
        $status = (string) ($_POST['status'] ?? 'configured');
        $endpointUrl = trim((string) ($_POST['endpoint_url'] ?? ''));
        $apiBaseUrl = trim((string) ($_POST['api_base_url'] ?? ''));
        $scanSubmitUrl = trim((string) ($_POST['scan_submit_url'] ?? ''));
        $resultUrl = trim((string) ($_POST['result_url'] ?? ''));
        $authType = trim((string) ($_POST['auth_type'] ?? ''));
        $documentationUrl = trim((string) ($_POST['documentation_url'] ?? ''));
        $description = trim((string) ($_POST['description'] ?? ''));
        $toolLogoPath = 'assets/img/cyber-logo.png';

        if ($projectId <= 0 || $name === '') {
            $error = 'Select a project and provide an add-on name.';
        } else {
            if (!empty($_FILES['tool_logo']['name']) && is_uploaded_file($_FILES['tool_logo']['tmp_name'])) {
                $logoDir = __DIR__ . '/uploads/tool-logos';
                if (!is_dir($logoDir)) {
                    mkdir($logoDir, 0775, true);
                }

                $extension = strtolower(pathinfo((string) $_FILES['tool_logo']['name'], PATHINFO_EXTENSION));
                $allowed = ['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg'];
                if (!in_array($extension, $allowed, true)) {
                    $error = 'Tool logo must be an image file.';
                } else {
                    $logoName = uniqid('tool-logo-', true) . '.' . $extension;
                    $logoTarget = $logoDir . DIRECTORY_SEPARATOR . $logoName;
                    if (move_uploaded_file($_FILES['tool_logo']['tmp_name'], $logoTarget)) {
                        $toolLogoPath = 'uploads/tool-logos/' . $logoName;
                    } else {
                        $error = 'Unable to save the uploaded tool logo.';
                    }
                }
            }
        }

        if (!$error) {
            $stmt = $pdo->prepare('INSERT INTO integrations (project_id, name, vendor_name, integration_profile, type, tool_category, connection_type, status, endpoint_url, api_base_url, scan_submit_url, result_url, auth_type, documentation_url, last_test_status, last_test_detail, tool_logo_path, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
            $stmt->execute([
                $projectId,
                $name,
                $vendorName !== '' ? $vendorName : null,
                $integrationProfile !== '' ? $integrationProfile : null,
                $type,
                $toolCategory,
                $connectionType,
                $status,
                $endpointUrl !== '' ? $endpointUrl : null,
                $apiBaseUrl !== '' ? $apiBaseUrl : null,
                $scanSubmitUrl !== '' ? $scanSubmitUrl : null,
                $resultUrl !== '' ? $resultUrl : null,
                $authType !== '' ? $authType : null,
                $documentationUrl !== '' ? $documentationUrl : null,
                'unknown',
                null,
                $toolLogoPath,
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
        <h1>Manage MobSF, assistant, paid scanners, and Python pentest integrations</h1>
        <p class="subhead">Register scanner, assistant, and safe pentest add-ons so the dashboard knows where to route mobile security, validation, commercial tool APIs, and triage workflows.</p>
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
        <label class="full">
          <span>Connector preset</span>
          <select id="integrationPreset" name="integration_preset">
            <?php foreach ($connectorPresets as $presetKey => $preset): ?>
              <option value="<?= e($presetKey) ?>"><?= e($preset['label']) ?></option>
            <?php endforeach; ?>
          </select>
        </label>
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
          <input type="text" name="name" placeholder="MobSF / OASM Assistant / Python Pentest Suite" required>
        </label>
        <label>
          <span>Vendor / platform</span>
          <input type="text" name="vendor_name" placeholder="OpenText / Veracode / Palo Alto / Custom">
        </label>
        <label>
          <span>Profile key</span>
          <input type="text" name="integration_profile" placeholder="webinspect / veracode / custom-paid-tool">
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
          <span>Tool category</span>
          <select name="tool_category">
            <option value="sast">SAST</option>
            <option value="dast">DAST</option>
            <option value="sca">SCA</option>
            <option value="mobile">Mobile</option>
            <option value="pentest">Pentest</option>
            <option value="assistant">Assistant</option>
            <option value="automation">Automation</option>
          </select>
        </label>
        <label>
          <span>Connection type</span>
          <select name="connection_type">
            <option value="docker">Docker</option>
            <option value="api">API</option>
            <option value="python">Python</option>
            <option value="manual">Manual</option>
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
          <span>API base URL</span>
          <input type="url" name="api_base_url" placeholder="https://api.vendor.example.com">
        </label>
        <label>
          <span>Submit endpoint</span>
          <input type="text" name="scan_submit_url" placeholder="/api/scan or /appsec/v1/scan">
        </label>
        <label>
          <span>Result endpoint</span>
          <input type="text" name="result_url" placeholder="/api/results or /appsec/v2/findings">
        </label>
        <label>
          <span>Auth type</span>
          <select name="auth_type">
            <option value="">Select auth</option>
            <option value="none">None</option>
            <option value="token">Token</option>
            <option value="bearer">Bearer</option>
            <option value="basic">Basic</option>
            <option value="oauth2">OAuth 2.0</option>
          </select>
        </label>
        <label class="full">
          <span>Documentation URL</span>
          <input type="url" name="documentation_url" placeholder="https://docs.vendor.example.com">
        </label>
        <label class="full">
          <span>Description</span>
          <textarea name="description" rows="4" placeholder="Describe what this add-on does for the program."></textarea>
        </label>
        <label class="full">
          <span>Tool logo</span>
          <input type="file" name="tool_logo" accept=".png,.jpg,.jpeg,.webp,.gif,.svg">
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
        <span class="muted">MobSF is available as a local service in Compose and paid tool APIs can be mapped here too</span>
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
                    <span class="tag"><?= e(strtoupper((string) $integration['type'])) ?></span>
                    <span class="tag"><?= e(toolCategoryLabel((string) ($integration['tool_category'] ?? 'automation'))) ?></span>
                    <span class="tag"><?= e(strtoupper((string) ($integration['connection_type'] ?? 'manual'))) ?></span>
                    <?php if (!empty($integration['integration_profile'])): ?><span class="tag"><?= e(strtoupper((string) $integration['integration_profile'])) ?></span><?php endif; ?>
                  </div>
                </div>
              </div>
              <span class="tag <?= e(integrationStatusClass((string) $integration['status'])) ?>"><?= e(strtoupper((string) $integration['status'])) ?></span>
            </div>
            <p><?= e((string) ($integration['description'] ?? '')) ?></p>
            <div class="finding-foot">
              <span><?= e((string) $integration['project_name']) ?></span>
              <span><?= e((string) ($integration['endpoint_url'] ?? 'n/a')) ?></span>
              <span><?= e((string) ($integration['api_base_url'] ?? '')) ?></span>
            </div>
            <div class="finding-foot">
              <span><?= e((string) ($integration['vendor_name'] ?? 'Custom vendor')) ?></span>
              <span><?= e((string) ($integration['auth_type'] ?? 'auth not set')) ?></span>
              <span><?= e((string) ($integration['documentation_url'] ?? '')) ?></span>
            </div>
            <div class="finding-foot">
              <span>Last test: <?= e((string) ($integration['last_tested_at'] ?? 'never')) ?></span>
              <span>Status: <?= e(strtoupper((string) ($integration['last_test_status'] ?? 'unknown'))) ?></span>
              <span><?= e((string) ($integration['last_test_detail'] ?? 'No test result yet.')) ?></span>
            </div>
            <div class="form-actions">
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                <input type="hidden" name="action" value="test_connection">
                <input type="hidden" name="integration_id" value="<?= (int) $integration['id'] ?>">
                <button class="button ghost" type="submit">Test connection</button>
              </form>
            </div>
          </article>
        <?php endforeach; ?>
      </div>
    </section>
  </div>
  <script>
    (function () {
      const presets = <?= json_encode($connectorPresets, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
      const preset = document.getElementById('integrationPreset');
      if (!preset) return;
      const fields = {
        vendor_name: document.querySelector('[name="vendor_name"]'),
        integration_profile: document.querySelector('[name="integration_profile"]'),
        type: document.querySelector('[name="type"]'),
        tool_category: document.querySelector('[name="tool_category"]'),
        connection_type: document.querySelector('[name="connection_type"]'),
        status: document.querySelector('[name="status"]'),
        endpoint_url: document.querySelector('[name="endpoint_url"]'),
        api_base_url: document.querySelector('[name="api_base_url"]'),
        scan_submit_url: document.querySelector('[name="scan_submit_url"]'),
        result_url: document.querySelector('[name="result_url"]'),
        auth_type: document.querySelector('[name="auth_type"]'),
        documentation_url: document.querySelector('[name="documentation_url"]'),
        description: document.querySelector('[name="description"]'),
      };

      const applyPreset = () => {
        const config = presets[preset.value] || presets.custom;
        Object.entries(fields).forEach(([key, input]) => {
          if (!input || config[key] === undefined) return;
          input.value = config[key];
        });
      };

      preset.addEventListener('change', applyPreset);
      applyPreset();
    })();
  </script>
</body>
</html>
