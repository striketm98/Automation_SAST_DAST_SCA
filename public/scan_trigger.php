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
$artifactPath = null;
$sourceMode = $sourceUrl !== '' ? 'url' : 'manual';

if (!in_array($scanKind, ['sast', 'sca', 'dast', 'mobile', 'suite'], true)) {
    $_SESSION['home_error'] = 'Invalid scan type selected.';
    header('Location: home.php');
    exit;
}

if (!empty($_FILES['source_archive']['name']) && is_uploaded_file($_FILES['source_archive']['tmp_name'])) {
    $uploadDir = __DIR__ . '/../storage/source-uploads';
    if (!is_dir($uploadDir)) {
        @mkdir($uploadDir, 0775, true);
    }
    $extension = strtolower(pathinfo((string) $_FILES['source_archive']['name'], PATHINFO_EXTENSION));
    $allowed = ['zip', 'apk', 'ipa', 'aab', 'tar', 'gz', 'tgz'];
    if (!in_array($extension, $allowed, true)) {
        $_SESSION['home_error'] = 'Uploaded source must be ZIP/APK/IPA/AAB/TAR/GZ/TGZ.';
        header('Location: home.php');
        exit;
    }
    $archiveName = uniqid('scan-source-', true) . '.' . $extension;
    $targetFile = $uploadDir . DIRECTORY_SEPARATOR . $archiveName;
    if (!move_uploaded_file($_FILES['source_archive']['tmp_name'], $targetFile)) {
        $_SESSION['home_error'] = 'Unable to save uploaded source file.';
        header('Location: home.php');
        exit;
    }
    $artifactPath = 'storage/source-uploads/' . $archiveName;
    $sourceMode = 'upload';
}

$sourceMeta = [
    'source_mode' => $sourceMode,
    'artifact_path' => $artifactPath,
    'source_name' => $artifactPath ? basename((string) $artifactPath) : null,
];

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

    if ($scanKind === 'suite') {
        $kinds = ['sast', 'dast', 'mobile']; // SonarQube + OWASP ZAP + MobSF
        $messages = [];
        $failed = false;
        foreach ($kinds as $kind) {
            $result = triggerScanFromUi(
                $pdo,
                (int) $project['id'],
                $kind,
                $targetUrl,
                $sourceUrl,
                $integrations,
                $sourceMeta
            );
            $messages[] = (string) ($result['message'] ?? strtoupper($kind) . ' trigger sent.');
            if (empty($result['ok'])) {
                $failed = true;
            }
        }
        if ($failed) {
            $_SESSION['home_error'] = 'Suite trigger completed with partial failures. ' . implode(' ', $messages);
        } else {
            $_SESSION['home_message'] = 'SonarQube + OWASP ZAP + MobSF suite started. ' . implode(' ', $messages);
        }
    } else {
        $result = triggerScanFromUi(
            $pdo,
            (int) $project['id'],
            $scanKind,
            $targetUrl,
            $sourceUrl,
            $integrations,
            $sourceMeta
        );

        if (!empty($result['ok'])) {
            $_SESSION['home_message'] = (string) ($result['message'] ?? 'Scan was initiated from UI.');
        } else {
            $_SESSION['home_error'] = (string) ($result['message'] ?? 'Unable to initiate scan.');
        }
    }
} catch (Throwable $e) {
    $_SESSION['home_error'] = 'Unable to initiate scan right now. Please try again.';
}

header('Location: home.php');
exit;
