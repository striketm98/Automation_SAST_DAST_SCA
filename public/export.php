<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$pdo = Database::pdo();
$format = strtolower((string) ($_GET['format'] ?? 'json'));

if ($pdo) {
    $project = $pdo->query('SELECT * FROM projects ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    if ($project) {
        $scanStmt = $pdo->prepare('SELECT * FROM scan_runs WHERE project_id = ? ORDER BY created_at DESC');
        $scanStmt->execute([$project['id']]);
        $scanRuns = $scanStmt->fetchAll();

        $findingStmt = $pdo->prepare('SELECT f.* FROM findings f INNER JOIN scan_runs s ON s.id = f.scan_run_id WHERE s.project_id = ? ORDER BY FIELD(f.severity, "critical","high","medium","low","info"), f.created_at DESC');
        $findingStmt->execute([$project['id']]);
        $findings = $findingStmt->fetchAll();
    } else {
        $dashboard = sampleDashboard();
        $project = $dashboard['project'];
        $scanRuns = $dashboard['scan_runs'];
        $findings = $dashboard['findings'];
    }
} else {
    $dashboard = sampleDashboard();
    $project = $dashboard['project'];
    $scanRuns = $dashboard['scan_runs'];
    $findings = $dashboard['findings'];
}

$payload = [
    'project' => $project,
    'scan_runs' => $scanRuns,
    'findings' => $findings,
    'generated_at' => date(DATE_ATOM),
];

if ($format === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="security-report.csv"');
    $out = fopen('php://output', 'wb');
    fputcsv($out, ['Severity', 'Status', 'CWE', 'Title', 'Category', 'File', 'Line', 'Description', 'Recommendation', 'Analyst Comment', 'AI Summary', 'AI Confidence']);
    foreach ($findings as $finding) {
        fputcsv($out, [
            $finding['severity'] ?? '',
            $finding['status'] ?? '',
            $finding['cwe_id'] ?? '',
            $finding['title'] ?? '',
            $finding['category'] ?? '',
            $finding['file_path'] ?? '',
            $finding['line_number'] ?? '',
            $finding['description'] ?? '',
            $finding['recommendation'] ?? '',
            $finding['analyst_comment'] ?? '',
            $finding['ai_summary'] ?? '',
            $finding['ai_confidence'] ?? '',
        ]);
    }
    fclose($out);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="security-report.json"');
echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
