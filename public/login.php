<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/helpers.php';

if (currentUser()) {
    header('Location: home.php');
    exit;
}

$error = $_SESSION['auth_error'] ?? null;
unset($_SESSION['auth_error']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Login</title>
  <link rel="icon" href="assets/img/favicon.ico">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body class="login-page">
  <main class="login-shell">
    <section class="login-hero">
      <div class="brand-lockup">
        <img src="assets/img/cyber-logo.png" alt="cyber-Security logo" class="brand-mark">
        <div>
          <p class="eyebrow">cyber-Security intelligence platform</p>
          <h1>Executive-ready cyber reporting in one secure workspace.</h1>
          <p class="subhead">Access a refined dashboard for SAST, DAST, SonarQube, ZAP, and dependency-risk oversight, designed for both leadership and delivery teams.</p>
        </div>
      </div>
      <div class="login-metrics">
        <div><strong>01</strong><span>Unified reporting</span></div>
        <div><strong>02</strong><span>Client-ready UI</span></div>
        <div><strong>03</strong><span>Structured review history</span></div>
      </div>
    </section>

    <section class="login-card">
      <div class="login-card-head">
        <span class="pill pill-success">Secure access</span>
        <h2>Sign in</h2>
        <p>Use your assigned credentials to review findings and reports.</p>
      </div>

      <?php if ($error): ?>
        <div class="notice danger"><?= e((string) $error) ?></div>
      <?php endif; ?>

      <form method="post" action="auth.php" class="login-form">
        <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
        <label>
          <span>Email</span>
          <input type="email" name="email" value="admin@cyber-security.local" required>
        </label>
        <label>
          <span>Password</span>
          <input type="password" name="password" placeholder="Enter your password" required>
        </label>
        <button class="button login-button" type="submit">Login</button>
      </form>
      <p class="login-foot">Demo account: <strong>admin@cyber-security.local</strong></p>
      <p class="login-foot">All demo users share the password: <strong>ChangeMe123!</strong></p>
      <p class="login-foot">Other demo users: manager@cyber-security.local, analyst@cyber-security.local, client@cyber-security.local</p>
    </section>
  </main>
</body>
</html>
