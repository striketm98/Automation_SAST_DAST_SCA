<?php

declare(strict_types=1);

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/helpers.php';

function authenticateFromRequest(): void
{
    $pdo = Database::pdo();
    $email = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $token = (string) ($_POST['csrf_token'] ?? '');

    if (!verifyCsrfToken($token)) {
        $_SESSION['auth_error'] = 'Your session expired. Please try again.';
        header('Location: login.php');
        exit;
    }

    if ($email === '' || $password === '' || !loginAttempt($email, $password, $pdo)) {
        $_SESSION['auth_error'] = 'Invalid email or password.';
        header('Location: login.php');
        exit;
    }

    header('Location: home.php');
    exit;
}
