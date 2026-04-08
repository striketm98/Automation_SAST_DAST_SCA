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

if ($format === 'xls') {
    header('Content-Type: application/vnd.ms-excel; charset=utf-8');
    header('Content-Disposition: attachment; filename="security-report.xls"');
    echo '<html><head><meta charset="UTF-8"></head><body>';
    echo '<table border="1">';
    echo '<tr><th>Severity</th><th>Status</th><th>CWE</th><th>Title</th><th>Category</th><th>File</th><th>Line</th><th>Description</th><th>Recommendation</th><th>Analyst Comment</th><th>AI Summary</th><th>AI Confidence</th></tr>';
    foreach ($findings as $finding) {
        echo '<tr>';
        foreach ([
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
        ] as $cell) {
            echo '<td>' . htmlspecialchars((string) $cell, ENT_QUOTES, 'UTF-8') . '</td>';
        }
        echo '</tr>';
    }
    echo '</table></body></html>';
    exit;
}

if ($format === 'doc') {
    header('Content-Type: application/msword; charset=utf-8');
    header('Content-Disposition: attachment; filename="security-report.doc"');
    echo '<html><head><meta charset="UTF-8"><title>Security Report</title></head><body>';
    echo '<h1>' . htmlspecialchars((string) $project['name'], ENT_QUOTES, 'UTF-8') . '</h1>';
    echo '<p>Prepared for ' . htmlspecialchars((string) $project['client_name'], ENT_QUOTES, 'UTF-8') . '</p>';
    echo '<h2>Findings</h2><table border="1" cellpadding="6" cellspacing="0"><tr><th>Severity</th><th>Status</th><th>CWE</th><th>Title</th><th>Recommendation</th></tr>';
    foreach ($findings as $finding) {
        echo '<tr>';
        echo '<td>' . htmlspecialchars((string) ($finding['severity'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars((string) ($finding['status'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars((string) ($finding['cwe_id'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars((string) ($finding['title'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>';
        echo '<td>' . htmlspecialchars((string) ($finding['recommendation'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>';
        echo '</tr>';
    }
    echo '</table></body></html>';
    exit;
}

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
