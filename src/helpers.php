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
            ['name' => 'MobSF', 'type' => 'scanner', 'status' => 'ready', 'endpoint_url' => 'http://localhost:8000', 'description' => 'Mobile application static and dynamic analysis add-on.'],
            ['name' => 'OASM Assistant', 'type' => 'assistant', 'status' => 'configured', 'endpoint_url' => 'https://oasm.example.local', 'description' => 'Intelligence assistant integration for threat triage and guidance.'],
        ],
        'findings' => [
            ['id' => 1, 'severity' => 'critical', 'status' => 'open', 'cwe_id' => 'CWE-78', 'analyst_comment' => '', 'ai_summary' => 'Likely command injection path with direct process execution.', 'ai_confidence' => 91, 'title' => 'Remote code execution pattern', 'category' => 'SAST', 'file_path' => 'app/services/parser.php', 'line_number' => 131, 'description' => 'Untrusted content is passed into a dynamic evaluator.', 'recommendation' => 'Remove the evaluator and replace it with a safe parser.'],
            ['id' => 2, 'severity' => 'high', 'status' => 'open', 'cwe_id' => 'CWE-352', 'analyst_comment' => '', 'ai_summary' => 'Missing anti-forgery controls on a state-changing form.', 'ai_confidence' => 88, 'title' => 'Missing CSRF protection', 'category' => 'DAST', 'file_path' => 'views/profile.php', 'line_number' => 42, 'description' => 'State-changing form does not include a CSRF token.', 'recommendation' => 'Add a CSRF token and verify it server-side.'],
            ['id' => 3, 'severity' => 'medium', 'status' => 'false_positive', 'cwe_id' => 'CWE-200', 'analyst_comment' => 'Vendor package risk is under review and appears informational.', 'ai_summary' => 'External package risk appears informational and should be manually confirmed.', 'ai_confidence' => 74, 'title' => 'Outdated dependency', 'category' => 'SCA', 'file_path' => 'composer.lock', 'line_number' => null, 'description' => 'A third-party package includes a known medium-risk vulnerability.', 'recommendation' => 'Upgrade to a patched version and re-run dependency analysis.'],
        ],
    ];
}
