<?php

declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function severityClass(string $severity): string
{
    return match ($severity) {
        'critical' => 'sev-critical',
        'high' => 'sev-high',
        'medium' => 'sev-medium',
        'low' => 'sev-low',
        default => 'sev-info',
    };
}

function findingStatusClass(string $status): string
{
    return match ($status) {
        'false_positive' => 'tag-false-positive',
        'accepted_risk' => 'tag-risk',
        'resolved' => 'tag-resolved',
        default => 'tag-open',
    };
}

function integrationStatusClass(string $status): string
{
    return match ($status) {
        'ready' => 'tag-resolved',
        'configured' => 'tag-risk',
        default => 'tag-open',
    };
}

function toolCategoryLabel(string $category): string
{
    return match ($category) {
        'sast' => 'SAST',
        'dast' => 'DAST',
        'sca' => 'SCA',
        'mobile' => 'Mobile',
        'pentest' => 'Pentest',
        'assistant' => 'Assistant',
        default => 'Automation',
    };
}

function cweCatalog(): array
{
    return [
        'CWE-89' => 'SQL Injection',
        'CWE-79' => 'Cross-Site Scripting',
        'CWE-78' => 'OS Command Injection',
        'CWE-22' => 'Path Traversal',
        'CWE-306' => 'Missing Authentication',
        'CWE-352' => 'CSRF',
        'CWE-798' => 'Use of Hard-coded Credentials',
        'CWE-200' => 'Information Exposure',
    ];
}

function cweRemediation(string $cweId): string
{
    return match ($cweId) {
        'CWE-89' => 'Use parameterized queries or prepared statements and validate all inputs.',
        'CWE-79' => 'Encode output, validate input, and apply context-aware escaping.',
        'CWE-78' => 'Avoid shell execution with untrusted input and use safe APIs.',
        'CWE-22' => 'Normalize paths and enforce strict allow-lists for file access.',
        'CWE-306' => 'Require authentication and verify access before protected actions.',
        'CWE-352' => 'Add CSRF tokens and verify them on every state-changing request.',
        'CWE-798' => 'Remove hard-coded credentials and load secrets from a secure store.',
        'CWE-200' => 'Reduce exposure and verify that the disclosure is intentional and necessary.',
        default => 'Review the code path, add defensive validation, and retest after remediation.',
    };
}

function inferCweId(array $item, string $sourceName = ''): ?string
{
    foreach (['cwe_id', 'cwe', 'cweid'] as $key) {
        if (!empty($item[$key])) {
            $value = strtoupper(trim((string) $item[$key]));
            return str_starts_with($value, 'CWE-') ? $value : ('CWE-' . preg_replace('/\D+/', '', $value));
        }
    }

    $haystack = strtolower(
        trim(
            implode(' ', array_filter([
                (string) ($item['title'] ?? ''),
                (string) ($item['message'] ?? ''),
                (string) ($item['description'] ?? ''),
                (string) ($item['desc'] ?? ''),
                (string) ($item['rule'] ?? ''),
                (string) $sourceName,
            ]))
        )
    );

    return match (true) {
        str_contains($haystack, 'sql injection') || str_contains($haystack, 'sqli') => 'CWE-89',
        str_contains($haystack, 'cross-site scripting') || str_contains($haystack, ' xss') || str_contains($haystack, 'xss ') => 'CWE-79',
        str_contains($haystack, 'command injection') || str_contains($haystack, 'shell') || str_contains($haystack, 'exec') => 'CWE-78',
        str_contains($haystack, 'csrf') => 'CWE-352',
        str_contains($haystack, 'path traversal') || str_contains($haystack, 'directory traversal') => 'CWE-22',
        str_contains($haystack, 'authentication') => 'CWE-306',
        str_contains($haystack, 'hard-coded') || str_contains($haystack, 'hardcoded') || str_contains($haystack, 'credential') => 'CWE-798',
        str_contains($haystack, 'exposure') || str_contains($haystack, 'information') => 'CWE-200',
        default => null,
    };
}

function normalizeSeverityLabel(string $severity, string $sourceName = ''): string
{
    $value = strtolower(trim($severity));
    return match ($value) {
        'blocker', 'critical', 'error', 'high', 'severe' => 'critical',
        'major', 'medium', 'warn', 'warning', 'moderate' => 'medium',
        'minor', 'low', 'info', 'information', 'notice' => 'low',
        default => str_contains(strtolower($sourceName), 'zap') ? 'medium' : 'low',
    };
}

function normalizeFindingFromImport(array $item, string $sourceName, string $toolName, string $scanType): array
{
    $title = trim((string) ($item['title'] ?? $item['name'] ?? $item['alert'] ?? $item['message'] ?? $item['rule'] ?? 'Imported finding'));
    $description = trim((string) ($item['description'] ?? $item['desc'] ?? $item['details'] ?? $item['message'] ?? $item['riskdesc'] ?? $title));
    $recommendation = trim((string) ($item['solution'] ?? $item['remediation'] ?? $item['fix'] ?? $item['recommendation'] ?? ''));
    $cweId = inferCweId($item, $sourceName);
    $category = match ($scanType) {
        'zap' => 'DAST',
        'sca' => 'SCA',
        'sonarqube' => 'SAST',
        default => (str_contains(strtolower($sourceName), 'mobsf') ? 'Mobile' : 'SAST'),
    };
    $severity = normalizeSeverityLabel((string) ($item['severity'] ?? $item['risk'] ?? $item['priority'] ?? $item['level'] ?? ''), $sourceName);
    $filePath = trim((string) ($item['file_path'] ?? $item['file'] ?? $item['component'] ?? $item['url'] ?? $item['path'] ?? ''));
    $lineNumber = null;
    foreach (['line', 'line_number', 'lineno', 'startline'] as $lineKey) {
        if (isset($item[$lineKey]) && is_numeric($item[$lineKey])) {
            $lineNumber = (int) $item[$lineKey];
            break;
        }
    }

    $issueSummary = trim((string) ($item['ai_issue_summary'] ?? $item['issue_summary'] ?? $item['summary'] ?? ''));
    if ($issueSummary === '') {
        $issueSummary = $title . ' detected from ' . $toolName . '.';
    }

    if ($recommendation === '') {
        $recommendation = $cweId ? cweRemediation($cweId) : 'Review the affected code path and apply a safe, tested fix.';
    }

    $validationNotes = trim((string) ($item['validation_notes'] ?? $item['evidence'] ?? $item['evidence_notes'] ?? ''));
    if ($validationNotes === '') {
        $evidenceParts = array_filter([
            trim((string) ($item['url'] ?? '')),
            trim((string) ($item['param'] ?? '')),
            trim((string) ($item['component'] ?? '')),
            trim((string) ($item['file'] ?? '')),
        ]);
        $validationNotes = $evidenceParts ? ('Safe validation evidence: ' . implode(', ', $evidenceParts)) : 'Safe validation evidence only. No exploit steps are stored in the platform.';
    }

    return [
        'severity' => $severity,
        'status' => 'open',
        'cwe_id' => $cweId,
        'title' => $title,
        'category' => $category,
        'file_path' => $filePath !== '' ? $filePath : null,
        'line_number' => $lineNumber,
        'description' => $description,
        'recommendation' => $recommendation,
        'ai_issue_summary' => $issueSummary,
        'ai_summary' => $issueSummary,
        'ai_remediation' => $recommendation,
        'validation_notes' => $validationNotes,
        'ai_confidence' => isset($item['confidence']) && is_numeric($item['confidence']) ? min(100, max(0, (int) $item['confidence'])) : null,
        'analyst_comment' => null,
    ];
}

function importedFindingCandidates(array $payload): array
{
    foreach (['findings', 'issues', 'alerts', 'vulnerabilities', 'results'] as $key) {
        if (!empty($payload[$key]) && is_array($payload[$key])) {
            return array_values(array_filter($payload[$key], 'is_array'));
        }
    }

    if (!empty($payload['data']) && is_array($payload['data'])) {
        return array_values(array_filter($payload['data'], 'is_array'));
    }

    return [];
}

function normalizeImportedFindings(string $sourceName, string $toolName, string $scanType, array $payload): array
{
    $candidates = importedFindingCandidates($payload);
    $findings = [];

    foreach ($candidates as $candidate) {
        $findings[] = normalizeFindingFromImport($candidate, $sourceName, $toolName, $scanType);
    }

    if (!$findings && !empty($payload)) {
        $findings[] = normalizeFindingFromImport($payload, $sourceName, $toolName, $scanType);
    }

    return $findings;
}

function ingestImportedFindings(PDO $pdo, int $scanRunId, string $sourceName, string $toolName, string $scanType, array $payload): int
{
    $findings = normalizeImportedFindings($sourceName, $toolName, $scanType, $payload);
    if (!$findings) {
        return 0;
    }

    $stmt = $pdo->prepare('
        INSERT INTO findings (
            scan_run_id, severity, status, cwe_id, ai_issue_summary, ai_summary, ai_remediation,
            validation_notes, ai_confidence, title, category, file_path, line_number, description,
            recommendation, analyst_comment
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ');

    $count = 0;
    foreach ($findings as $finding) {
        $stmt->execute([
            $scanRunId,
            $finding['severity'],
            $finding['status'],
            $finding['cwe_id'],
            $finding['ai_issue_summary'],
            $finding['ai_summary'],
            $finding['ai_remediation'],
            $finding['validation_notes'],
            $finding['ai_confidence'],
            $finding['title'],
            $finding['category'],
            $finding['file_path'],
            $finding['line_number'],
            $finding['description'],
            $finding['recommendation'],
            $finding['analyst_comment'],
        ]);
        $count++;
    }

    return $count;
}

function pentestPlaybook(): array
{
    return [
        [
            'title' => 'Authentication review',
            'summary' => 'Validate login behavior, session expiry, and access control outcomes.',
        ],
        [
            'title' => 'Input validation review',
            'summary' => 'Check server-side validation, output encoding, and request handling.',
        ],
        [
            'title' => 'Mobile configuration review',
            'summary' => 'Confirm transport security, local storage, and API usage rules.',
        ],
        [
            'title' => 'Dependency exposure review',
            'summary' => 'Track advisory status, package versions, and remediation evidence.',
        ],
    ];
}

function pentestChecklist(): array
{
    return [
        ['section' => 'Access control', 'items' => ['Login works as expected', 'Session expires on logout', 'Role restrictions enforced', 'Admin pages are protected']],
        ['section' => 'Input handling', 'items' => ['Server-side validation is present', 'Output encoding is context-aware', 'File uploads are restricted', 'Error messages do not leak secrets']],
        ['section' => 'Security headers', 'items' => ['HSTS enabled', 'CSP reviewed', 'X-Frame-Options or frame-ancestors set', 'Cookies use Secure and HttpOnly']],
        ['section' => 'Mobile / API', 'items' => ['Transport security is enforced', 'Sensitive data is not stored locally', 'API auth is required', 'No excessive data in responses']],
        ['section' => 'Evidence', 'items' => ['Screenshots captured', 'Validation notes stored', 'CWE mapped', 'Remediation confirmed after retest']],
    ];
}

function oasmAssetSamples(): array
{
    return [
        ['asset_type' => 'domain', 'asset_name' => 'client.example.com', 'asset_url' => 'https://client.example.com', 'exposure' => 'public', 'status' => 'reviewed', 'notes' => 'Primary portal under ongoing monitoring.'],
        ['asset_type' => 'api', 'asset_name' => 'api.client.example.com', 'asset_url' => 'https://api.client.example.com', 'exposure' => 'public', 'status' => 'discovered', 'notes' => 'API surface queued for validation.'],
        ['asset_type' => 'subdomain', 'asset_name' => 'dev.client.example.com', 'asset_url' => 'https://dev.client.example.com', 'exposure' => 'internal', 'status' => 'in_scope', 'notes' => 'Internal environment tracked for exposure control.'],
        ['asset_type' => 'repo', 'asset_name' => 'github.com/acme/repo', 'asset_url' => 'https://github.com/acme/repo', 'exposure' => 'restricted', 'status' => 'out_of_scope', 'notes' => 'Reference only; not in current assessment.'],
    ];
}

function toolHealth(string $endpointUrl): array
{
    $endpointUrl = trim($endpointUrl);
    if ($endpointUrl === '') {
        return ['status' => 'unknown', 'label' => 'Unknown', 'detail' => 'No endpoint configured'];
    }

    $healthUrl = rtrim($endpointUrl, '/') . '/health';
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 2,
            'ignore_errors' => true,
        ],
    ]);

    $body = @file_get_contents($healthUrl, false, $context);
    if ($body === false) {
        return ['status' => 'down', 'label' => 'Down', 'detail' => $healthUrl];
    }

    $decoded = json_decode($body, true);
    if (is_array($decoded) && (($decoded['status'] ?? '') === 'ok' || ($decoded['status'] ?? '') === 'ready')) {
        return ['status' => 'up', 'label' => 'Up', 'detail' => $healthUrl];
    }

    return ['status' => 'partial', 'label' => 'Partial', 'detail' => $healthUrl];
}

function findIntegrationForScan(array $integrations, string $scanKind): ?array
{
    $scanKind = strtolower(trim($scanKind));
    $profiles = match ($scanKind) {
        'sast' => ['sonarqube'],
        'sca' => ['dependency-check', 'dependency_check'],
        'dast' => ['zap'],
        'mobile' => ['mobsf'],
        default => [],
    };
    $categories = match ($scanKind) {
        'sast' => ['sast'],
        'sca' => ['sca'],
        'dast' => ['dast'],
        'mobile' => ['mobile'],
        default => [],
    };

    foreach ($integrations as $integration) {
        $profile = strtolower((string) ($integration['integration_profile'] ?? ''));
        if ($profile !== '' && in_array($profile, $profiles, true)) {
            return $integration;
        }
    }

    foreach ($integrations as $integration) {
        $category = strtolower((string) ($integration['tool_category'] ?? ''));
        if ($category !== '' && in_array($category, $categories, true)) {
            return $integration;
        }
    }

    return null;
}

function triggerScanFromUi(PDO $pdo, int $projectId, string $scanKind, string $targetUrl, string $sourceUrl, array $integrations): array
{
    $scanKind = strtolower(trim($scanKind));
    $scanType = match ($scanKind) {
        'sast' => 'sonarqube',
        'sca' => 'sca',
        'dast' => 'zap',
        'mobile' => 'sast',
        default => 'sast',
    };
    $toolLabel = match ($scanKind) {
        'sast' => 'SAST',
        'sca' => 'SCA',
        'dast' => 'DAST',
        'mobile' => 'Mobile APK',
        default => strtoupper($scanKind),
    };
    $integration = findIntegrationForScan($integrations, $scanKind);
    $integrationId = !empty($integration['id']) ? (int) $integration['id'] : null;
    $toolName = (string) ($integration['name'] ?? ($toolLabel . ' Connector'));
    $actor = (string) (currentUser()['email'] ?? 'system');

    $summary = sprintf(
        '%s scan initiated from UI by %s. Target: %s',
        $toolLabel,
        $actor,
        $targetUrl !== '' ? $targetUrl : 'n/a'
    );

    $scanStmt = $pdo->prepare('INSERT INTO scan_runs (project_id, scan_type, tool_name, status, started_at, summary, raw_payload) VALUES (?, ?, ?, ?, NOW(), ?, ?)');
    $scanStmt->execute([
        $projectId,
        $scanType,
        $toolName,
        'queued',
        $summary,
        json_encode(['scan_kind' => $scanKind, 'target_url' => $targetUrl, 'source_url' => $sourceUrl], JSON_UNESCAPED_SLASHES),
    ]);
    $scanRunId = (int) $pdo->lastInsertId();

    $requestPayload = [
        'project_id' => $projectId,
        'scan_run_id' => $scanRunId,
        'scan_kind' => $scanKind,
        'target_url' => $targetUrl,
        'source_url' => $sourceUrl,
        'requested_by' => $actor,
    ];

    $jobStmt = $pdo->prepare('INSERT INTO scan_jobs (project_id, scan_run_id, integration_id, scan_kind, status, target_url, source_url, request_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    $jobStmt->execute([
        $projectId,
        $scanRunId,
        $integrationId,
        $scanKind,
        'queued',
        $targetUrl !== '' ? $targetUrl : null,
        $sourceUrl !== '' ? $sourceUrl : null,
        json_encode($requestPayload, JSON_UNESCAPED_SLASHES),
    ]);
    $jobId = (int) $pdo->lastInsertId();

    if (!$integration) {
        return [
            'ok' => true,
            'message' => $toolLabel . ' scan queued in UI. Add connector details in Add-ons to submit automatically.',
            'scan_run_id' => $scanRunId,
            'job_id' => $jobId,
        ];
    }

    $base = trim((string) ($integration['api_base_url'] ?? $integration['endpoint_url'] ?? ''));
    $submitPath = trim((string) ($integration['scan_submit_url'] ?? ''));
    if ($base === '') {
        return [
            'ok' => true,
            'message' => $toolLabel . ' scan queued. Connector endpoint is not configured yet.',
            'scan_run_id' => $scanRunId,
            'job_id' => $jobId,
        ];
    }

    $submitUrl = rtrim($base, '/');
    if ($submitPath !== '') {
        $submitUrl .= '/' . ltrim($submitPath, '/');
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => json_encode($requestPayload, JSON_UNESCAPED_SLASHES),
            'timeout' => 4,
            'ignore_errors' => true,
        ],
    ]);

    $response = @file_get_contents($submitUrl, false, $context);
    if ($response === false) {
        $pdo->prepare('UPDATE scan_jobs SET status = ?, error_message = ? WHERE id = ?')
            ->execute(['queued', 'Connector unreachable. Job is queued for manual execution.', $jobId]);
        return [
            'ok' => true,
            'message' => $toolLabel . ' scan queued. Connector is unreachable right now.',
            'scan_run_id' => $scanRunId,
            'job_id' => $jobId,
        ];
    }

    $decodedResponse = json_decode($response, true);
    $responsePayload = is_array($decodedResponse)
        ? $decodedResponse
        : ['raw_response' => substr($response, 0, 4000)];

    $pdo->prepare('UPDATE scan_jobs SET status = ?, response_payload = ? WHERE id = ?')
        ->execute(['submitted', json_encode($responsePayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $jobId]);
    $pdo->prepare('UPDATE scan_runs SET status = ?, summary = ? WHERE id = ?')
        ->execute([
            'running',
            sprintf('%s scan submitted to %s and is now running.', $toolLabel, $toolName),
            $scanRunId,
        ]);

    return [
        'ok' => true,
        'message' => $toolLabel . ' scan submitted successfully.',
        'scan_run_id' => $scanRunId,
        'job_id' => $jobId,
    ];
}

function logOasmHistory(PDO $pdo, ?int $projectId, ?int $assetId, string $action, string $details): void
{
    if (!$projectId) {
        return;
    }

    $actor = currentUser()['display_name'] ?? currentUser()['email'] ?? 'system';
    $stmt = $pdo->prepare('INSERT INTO attack_surface_history (project_id, asset_id, action, actor, details) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([
        $projectId,
        $assetId,
        $action,
        $actor,
        $details !== '' ? $details : null,
    ]);
}

function parseOasmAssetPayload(string $payload): array
{
    $decoded = json_decode($payload, true);
    if (!is_array($decoded)) {
        return [];
    }

    $records = [];
    $items = [];
    foreach (['assets', 'items', 'data'] as $key) {
        if (!empty($decoded[$key]) && is_array($decoded[$key])) {
            $items = array_values(array_filter($decoded[$key], 'is_array'));
            break;
        }
    }

    if (!$items && array_is_list($decoded)) {
        $items = array_values(array_filter($decoded, 'is_array'));
    }

    foreach ($items ?: [$decoded] as $item) {
        $records[] = [
            'asset_type' => (string) ($item['asset_type'] ?? $item['type'] ?? 'url'),
            'asset_name' => (string) ($item['asset_name'] ?? $item['name'] ?? $item['host'] ?? $item['url'] ?? 'Imported asset'),
            'asset_url' => (string) ($item['asset_url'] ?? $item['url'] ?? ''),
            'exposure' => (string) ($item['exposure'] ?? 'public'),
            'status' => (string) ($item['status'] ?? 'discovered'),
            'notes' => (string) ($item['notes'] ?? $item['description'] ?? 'Imported from JSON feed.'),
        ];
    }

    return $records;
}

function appName(): string
{
    return getenv('APP_NAME') ?: 'cyber-Security';
}

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function currentUserRole(): string
{
    return (string) (currentUser()['role'] ?? 'guest');
}

function requireLogin(): void
{
    if (!currentUser()) {
        header('Location: login.php');
        exit;
    }
}

function requireRole(array $roles): void
{
    requireLogin();
    if (!in_array(currentUserRole(), $roles, true)) {
        header('Location: index.php');
        exit;
    }
}

function loginAttempt(string $email, string $password, ?PDO $pdo): bool
{
    $hash = null;
    if ($pdo) {
        try {
            $stmt = $pdo->prepare('SELECT email, display_name, password_sha256, role FROM users WHERE email = ? LIMIT 1');
            $stmt->execute([$email]);
            $hash = $stmt->fetch();
        } catch (Throwable $e) {
            $stmt = $pdo->prepare('SELECT email, display_name, password_sha256 FROM users WHERE email = ? LIMIT 1');
            $stmt->execute([$email]);
            $hash = $stmt->fetch();
            if (is_array($hash)) {
                $hash['role'] = 'admin';
            }
        }
    }

    if (!$hash) {
        return false;
    }

    $candidate = hash('sha256', $password);
    if (!hash_equals((string) $hash['password_sha256'], $candidate)) {
        return false;
    }

    $_SESSION['user'] = [
        'email' => $hash['email'],
        'display_name' => $hash['display_name'],
        'role' => (string) ($hash['role'] ?? 'guest'),
    ];

    return true;
}

function logoutUser(): void
{
    unset($_SESSION['user']);
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }

    return (string) $_SESSION['csrf_token'];
}

function verifyCsrfToken(?string $token): bool
{
    return isset($_SESSION['csrf_token']) && is_string($token) && hash_equals((string) $_SESSION['csrf_token'], $token);
}

function sampleDashboard(): array
{
    return [
        'project' => [
            'name' => 'Client Portal',
            'client_name' => 'Acme Corporation',
            'repository_url' => 'https://example.com/repo',
            'target_url' => 'https://example.com/app',
        ],
        'metrics' => [
            'open_findings' => 12,
            'critical' => 1,
            'high' => 3,
            'medium' => 4,
            'low' => 4,
            'coverage' => 78,
            'quality_gate' => 'Passed with warnings',
        ],
        'scan_runs' => [
            ['tool_name' => 'SonarQube', 'scan_type' => 'sonarqube', 'status' => 'completed', 'summary' => 'Code quality profile uploaded from SonarQube.', 'completed_at' => '2026-04-05 14:12:00'],
            ['tool_name' => 'OWASP ZAP', 'scan_type' => 'zap', 'status' => 'completed', 'summary' => 'DAST baseline run completed.', 'completed_at' => '2026-04-06 09:30:00'],
            ['tool_name' => 'Dependency-Check', 'scan_type' => 'sca', 'status' => 'completed', 'summary' => 'Open-source dependency review completed.', 'completed_at' => '2026-04-07 18:20:00'],
        ],
        'integrations' => [
            ['name' => 'MobSF', 'vendor_name' => 'MobSF', 'integration_profile' => 'mobsf', 'type' => 'scanner', 'tool_category' => 'mobile', 'connection_type' => 'docker', 'status' => 'ready', 'endpoint_url' => 'http://localhost:8000', 'api_base_url' => 'http://localhost:8000', 'scan_submit_url' => '/api/v1/scan', 'result_url' => '/api/v1/report', 'auth_type' => 'token', 'documentation_url' => 'https://github.com/MobSF/docs', 'last_test_status' => 'up', 'last_test_detail' => 'Demo endpoint reachable', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Mobile application static and dynamic analysis add-on.'],
            ['name' => 'OASM Assistant', 'vendor_name' => 'cyber-Security', 'integration_profile' => 'oasm-assistant', 'type' => 'assistant', 'tool_category' => 'assistant', 'connection_type' => 'api', 'status' => 'configured', 'endpoint_url' => 'https://oasm.example.local', 'api_base_url' => 'https://oasm.example.local', 'scan_submit_url' => '/api/summary', 'result_url' => '/api/assets', 'auth_type' => 'bearer', 'documentation_url' => '', 'last_test_status' => 'unknown', 'last_test_detail' => 'No test result yet', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Intelligence assistant integration for threat triage and guidance.'],
            ['name' => 'OWASP ZAP', 'vendor_name' => 'OWASP', 'integration_profile' => 'zap', 'type' => 'scanner', 'tool_category' => 'dast', 'connection_type' => 'docker', 'status' => 'ready', 'endpoint_url' => 'http://localhost:8090', 'api_base_url' => 'http://localhost:8090', 'scan_submit_url' => '/JSON/spider/action/scan/', 'result_url' => '/JSON/core/view/alerts/', 'auth_type' => 'none', 'documentation_url' => 'https://www.zaproxy.org/docs/', 'last_test_status' => 'up', 'last_test_detail' => 'Demo endpoint reachable', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Dynamic application security testing engine for baseline and authenticated scans.'],
            ['name' => 'SonarQube', 'vendor_name' => 'SonarSource', 'integration_profile' => 'sonarqube', 'type' => 'scanner', 'tool_category' => 'sast', 'connection_type' => 'docker', 'status' => 'ready', 'endpoint_url' => 'http://localhost:9000', 'api_base_url' => 'http://localhost:9000', 'scan_submit_url' => '/api/issues/search', 'result_url' => '/api/measures/component', 'auth_type' => 'token', 'documentation_url' => 'https://docs.sonarsource.com/', 'last_test_status' => 'up', 'last_test_detail' => 'Demo endpoint reachable', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Source-code quality and static analysis platform.'],
            ['name' => 'Dependency-Check', 'vendor_name' => 'OWASP', 'integration_profile' => 'dependency-check', 'type' => 'scanner', 'tool_category' => 'sca', 'connection_type' => 'docker', 'status' => 'ready', 'endpoint_url' => 'http://localhost:3300', 'api_base_url' => 'http://localhost:3300', 'scan_submit_url' => '/api/report', 'result_url' => '/api/report', 'auth_type' => 'none', 'documentation_url' => 'https://jeremylong.github.io/DependencyCheck/', 'last_test_status' => 'up', 'last_test_detail' => 'Demo endpoint reachable', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Open-source dependency and vulnerability analysis.'],
            ['name' => 'sqlmap', 'vendor_name' => 'sqlmap', 'integration_profile' => 'sqlmap', 'type' => 'scanner', 'tool_category' => 'pentest', 'connection_type' => 'python', 'status' => 'configured', 'endpoint_url' => 'http://localhost:6000', 'api_base_url' => 'http://localhost:6000', 'scan_submit_url' => '/run', 'result_url' => '/results', 'auth_type' => 'token', 'documentation_url' => 'https://sqlmap.org/', 'last_test_status' => 'unknown', 'last_test_detail' => 'No test result yet', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Authorized SQL injection testing container for controlled assessments.'],
            ['name' => 'Python Pentest Suite', 'vendor_name' => 'cyber-Security', 'integration_profile' => 'python-pentest-suite', 'type' => 'automation', 'tool_category' => 'pentest', 'connection_type' => 'python', 'status' => 'ready', 'endpoint_url' => 'http://pentest-python:6100', 'api_base_url' => 'http://pentest-python:6100', 'scan_submit_url' => '/catalog', 'result_url' => '/summary', 'auth_type' => 'none', 'documentation_url' => '', 'last_test_status' => 'up', 'last_test_detail' => 'Demo endpoint reachable', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Python-based authorized validation companion for safe checks, evidence notes, and remediation planning.'],
            ['name' => 'Open Attack Surface Management', 'vendor_name' => 'cyber-Security', 'integration_profile' => 'oasm', 'type' => 'assistant', 'tool_category' => 'assistant', 'connection_type' => 'api', 'status' => 'ready', 'endpoint_url' => 'http://oasm:6200', 'api_base_url' => 'http://oasm:6200', 'scan_submit_url' => '/assets', 'result_url' => '/summary', 'auth_type' => 'none', 'documentation_url' => '', 'last_test_status' => 'up', 'last_test_detail' => 'Demo endpoint reachable', 'tool_logo_path' => 'assets/img/cyber-logo.png', 'description' => 'Attack-surface inventory and exposure tracking module for approved assets.'],
        ],
        'findings' => [
            ['id' => 1, 'severity' => 'critical', 'status' => 'open', 'claim_state' => 'unclaimed', 'claimed_by' => null, 'claimed_at' => null, 'cwe_id' => 'CWE-78', 'analyst_comment' => '', 'ai_issue_summary' => 'Likely command injection path with direct process execution.', 'ai_summary' => 'Likely command injection path with direct process execution.', 'ai_remediation' => 'Remove the evaluator and replace it with a safe parser.', 'validation_notes' => 'Validate with unit tests and safe input cases only. Do not store exploit steps.', 'ai_confidence' => 91, 'title' => 'Remote code execution pattern', 'category' => 'SAST', 'file_path' => 'app/services/parser.php', 'line_number' => 131, 'description' => 'Untrusted content is passed into a dynamic evaluator.', 'recommendation' => 'Remove the evaluator and replace it with a safe parser.'],
            ['id' => 2, 'severity' => 'high', 'status' => 'open', 'claim_state' => 'unclaimed', 'claimed_by' => null, 'claimed_at' => null, 'cwe_id' => 'CWE-352', 'analyst_comment' => '', 'ai_issue_summary' => 'Missing anti-forgery controls on a state-changing form.', 'ai_summary' => 'Missing anti-forgery controls on a state-changing form.', 'ai_remediation' => 'Add a CSRF token and verify it server-side.', 'validation_notes' => 'Confirm token rejection on missing and stale submissions.', 'ai_confidence' => 88, 'title' => 'Missing CSRF protection', 'category' => 'DAST', 'file_path' => 'views/profile.php', 'line_number' => 42, 'description' => 'State-changing form does not include a CSRF token.', 'recommendation' => 'Add a CSRF token and verify it server-side.'],
            ['id' => 3, 'severity' => 'medium', 'status' => 'false_positive', 'claim_state' => 'unclaimed', 'claimed_by' => null, 'claimed_at' => null, 'cwe_id' => 'CWE-200', 'analyst_comment' => 'Vendor package risk is under review and appears informational.', 'ai_issue_summary' => 'External package risk appears informational and should be manually confirmed.', 'ai_summary' => 'External package risk appears informational and should be manually confirmed.', 'ai_remediation' => 'Upgrade to a patched version and re-run dependency analysis.', 'validation_notes' => 'Check upstream advisories and package changelog before closing.', 'ai_confidence' => 74, 'title' => 'Outdated dependency', 'category' => 'SCA', 'file_path' => 'composer.lock', 'line_number' => null, 'description' => 'A third-party package includes a known medium-risk vulnerability.', 'recommendation' => 'Upgrade to a patched version and re-run dependency analysis.'],
        ],
    ];
}
