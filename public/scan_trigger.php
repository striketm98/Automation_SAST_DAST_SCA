<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireRole(['admin', 'manager', 'analyst']);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: home.php');
    exit;
}

$pdo = Database::pdo();
if (!$pdo) {
    $_SESSION['home_error'] = 'Database is unavailable. Start MySQL and try again.';
    header('Location: home.php');
    exit;
}

if (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
    $_SESSION['home_error'] = 'Session expired. Please try again.';
    header('Location: home.php');
    exit;
}

$scanKind = strtolower(trim((string) ($_POST['scan_kind'] ?? '')));
$targetUrl = trim((string) ($_POST['target_url'] ?? ''));
$sourceUrl = trim((string) ($_POST['source_url'] ?? ''));

if (!in_array($scanKind, ['sast', 'sca', 'dast', 'mobile'], true)) {
    $_SESSION['home_error'] = 'Invalid scan type selected.';
    header('Location: home.php');
    exit;
}

try {
    $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    if (!$project) {
        $_SESSION['home_error'] = 'No project found. Please onboard a client first.';
        header('Location: home.php');
        exit;
    }

    $integrations = [];
    try {
        $stmt = $pdo->prepare('SELECT * FROM integrations WHERE project_id = ? ORDER BY created_at DESC');
        $stmt->execute([(int) $project['id']]);
        $integrations = $stmt->fetchAll() ?: [];
    } catch (Throwable $e) {
        $integrations = [];
    }

    $result = triggerScanFromUi(
        $pdo,
        (int) $project['id'],
        $scanKind,
        $targetUrl,
        $sourceUrl,
        $integrations
    );

    if (!empty($result['ok'])) {
        $_SESSION['home_message'] = (string) ($result['message'] ?? 'Scan was initiated from UI.');
    } else {
        $_SESSION['home_error'] = (string) ($result['message'] ?? 'Unable to initiate scan.');
    }
} catch (Throwable $e) {
    $_SESSION['home_error'] = 'Unable to initiate scan right now. Please try again.';
}

header('Location: home.php');
exit;
