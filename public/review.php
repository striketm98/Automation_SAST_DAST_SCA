<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$pdo) {
    header('Location: report.php');
    exit;
}

if (!verifyCsrfToken((string) ($_POST['csrf_token'] ?? ''))) {
    $_SESSION['review_error'] = 'Your review session expired. Please try again.';
    header('Location: report.php');
    exit;
}

$findingId = (int) ($_POST['finding_id'] ?? 0);
$status = (string) ($_POST['status'] ?? 'open');
$comment = trim((string) ($_POST['analyst_comment'] ?? ''));
$cweId = trim((string) ($_POST['cwe_id'] ?? ''));
$aiIssueSummary = trim((string) ($_POST['ai_issue_summary'] ?? ''));
$aiSummary = trim((string) ($_POST['ai_summary'] ?? ''));
$aiRemediation = trim((string) ($_POST['ai_remediation'] ?? ''));
$validationNotes = trim((string) ($_POST['validation_notes'] ?? ''));
$aiConfidence = (int) ($_POST['ai_confidence'] ?? 0);

$allowedStatus = ['open', 'false_positive', 'accepted_risk', 'resolved'];
if ($findingId <= 0 || !in_array($status, $allowedStatus, true)) {
    $_SESSION['review_error'] = 'Invalid review data.';
    header('Location: report.php');
    exit;
}

$stmt = $pdo->prepare('UPDATE findings SET status = ?, analyst_comment = ?, cwe_id = ?, ai_issue_summary = ?, ai_summary = ?, ai_remediation = ?, validation_notes = ?, ai_confidence = ? WHERE id = ?');
$stmt->execute([
    $status,
    $comment !== '' ? $comment : null,
    $cweId !== '' ? $cweId : null,
    $aiIssueSummary !== '' ? $aiIssueSummary : null,
    $aiSummary !== '' ? $aiSummary : null,
    $aiRemediation !== '' ? $aiRemediation : null,
    $validationNotes !== '' ? $validationNotes : null,
    $aiConfidence > 0 ? min($aiConfidence, 100) : null,
    $findingId,
]);

$_SESSION['review_success'] = 'Finding review saved.';
header('Location: report.php');
exit;
