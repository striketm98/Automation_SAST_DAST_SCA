<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/auth.php';
requireLogin();

$tabs = [
    ['label' => 'Pentest checklist', 'href' => 'checklist.php', 'active' => true],
    ['label' => 'Open ASM', 'href' => 'oasm.php', 'active' => false],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= e(appName()) ?> Pentest Checklist</title>
  <link rel="icon" href="assets/img/cyber-logo.png">
  <link rel="stylesheet" href="assets/css/app.css">
</head>
<body>
  <div class="page-shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">Pentest checklist</p>
        <h1>Authorized validation checklist</h1>
        <p class="subhead">Use this tab to track safe validation points, coverage, and evidence without storing exploit instructions.</p>
      </div>
      <div class="topbar-actions">
        <a class="button ghost" href="home.php">Dashboard</a>
        <a class="button ghost" href="audit.php">Audit</a>
        <a class="button" href="oasm.php">Open ASM</a>
      </div>
    </header>

    <div class="tab-strip">
      <?php foreach ($tabs as $tab): ?>
        <a class="tab-link <?= $tab['active'] ? 'active' : '' ?>" href="<?= e($tab['href']) ?>"><?= e($tab['label']) ?></a>
      <?php endforeach; ?>
    </div>

    <section class="panel wide">
      <div class="panel-header">
        <h3>Checklist coverage</h3>
        <span class="muted">Review each area before marking a finding as validated or false positive</span>
      </div>
      <div class="checklist-grid">
        <?php foreach (pentestChecklist() as $group): ?>
          <article class="checklist-card">
            <h4><?= e((string) $group['section']) ?></h4>
            <ul class="checklist-list">
              <?php foreach ($group['items'] as $item): ?>
                <li><span class="check-dot"></span><span><?= e((string) $item) ?></span></li>
              <?php endforeach; ?>
            </ul>
          </article>
        <?php endforeach; ?>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h3>Safe evidence guidance</h3>
        <span class="muted">Record outcome, not exploit steps</span>
      </div>
      <div class="access-grid">
        <div><span>Store</span><strong>Screenshots, headers, log excerpts, and retest results</strong></div>
        <div><span>Avoid</span><strong>Exploit payloads, weaponized PoC steps, or destructive actions</strong></div>
        <div><span>Map</span><strong>CWE, severity, and remediation owner</strong></div>
        <div><span>Close</span><strong>Only after validation on a patched build</strong></div>
      </div>
    </section>
  </div>
</body>
</html>
