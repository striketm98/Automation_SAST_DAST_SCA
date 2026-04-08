<?php

declare(strict_types=1);

final class Database
{
    public static function pdo(): ?PDO
    {
        $host = getenv('DB_HOST') ?: 'db';
        $port = getenv('DB_PORT') ?: '3306';
        $name = getenv('DB_NAME') ?: 'security_dashboard';
        $user = getenv('DB_USER') ?: 'dashboard';
        $pass = getenv('DB_PASSWORD') ?: 'dashboard123';

        try {
            $pdo = new PDO(
                "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4",
                $user,
                $pass,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]
            );

            self::ensureCoreSchema($pdo);
            return $pdo;
        } catch (Throwable $e) {
            return null;
        }
    }

    private static function ensureCoreSchema(PDO $pdo): void
    {
        self::runSchemaStatement($pdo, "
            CREATE TABLE IF NOT EXISTS integrations (
              id INT AUTO_INCREMENT PRIMARY KEY,
              project_id INT NOT NULL,
              name VARCHAR(120) NOT NULL,
              vendor_name VARCHAR(120) DEFAULT NULL,
              integration_profile VARCHAR(80) DEFAULT NULL,
              type ENUM('scanner','assistant','automation') NOT NULL DEFAULT 'scanner',
              tool_category ENUM('sast','dast','sca','mobile','pentest','assistant','automation') NOT NULL DEFAULT 'automation',
              connection_type ENUM('docker','api','python','manual') NOT NULL DEFAULT 'manual',
              status ENUM('configured','ready','disabled') NOT NULL DEFAULT 'ready',
              endpoint_url VARCHAR(255) DEFAULT NULL,
              api_base_url VARCHAR(255) DEFAULT NULL,
              scan_submit_url VARCHAR(255) DEFAULT NULL,
              result_url VARCHAR(255) DEFAULT NULL,
              auth_type VARCHAR(40) DEFAULT NULL,
              documentation_url VARCHAR(255) DEFAULT NULL,
              last_tested_at DATETIME DEFAULT NULL,
              last_test_status ENUM('unknown','up','down','partial') NOT NULL DEFAULT 'unknown',
              last_test_detail VARCHAR(255) DEFAULT NULL,
              tool_logo_path VARCHAR(255) DEFAULT NULL,
              description TEXT DEFAULT NULL,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");

        self::runSchemaStatement($pdo, "
            CREATE TABLE IF NOT EXISTS attack_surface_assets (
              id INT AUTO_INCREMENT PRIMARY KEY,
              project_id INT NOT NULL,
              asset_type ENUM('domain','subdomain','ip','url','api','mobile','repo') NOT NULL DEFAULT 'url',
              asset_name VARCHAR(160) NOT NULL,
              asset_url VARCHAR(255) DEFAULT NULL,
              exposure ENUM('public','internal','restricted') NOT NULL DEFAULT 'public',
              status ENUM('discovered','reviewed','in_scope','out_of_scope') NOT NULL DEFAULT 'discovered',
              notes TEXT DEFAULT NULL,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");

        self::runSchemaStatement($pdo, "
            CREATE TABLE IF NOT EXISTS attack_surface_history (
              id INT AUTO_INCREMENT PRIMARY KEY,
              project_id INT NOT NULL,
              asset_id INT DEFAULT NULL,
              action VARCHAR(40) NOT NULL,
              actor VARCHAR(160) NOT NULL DEFAULT 'system',
              details TEXT DEFAULT NULL,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");

        self::runSchemaStatement($pdo, "
            ALTER TABLE attack_surface_history
              ADD COLUMN IF NOT EXISTS asset_id INT DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS actor VARCHAR(160) NOT NULL DEFAULT 'system',
              ADD COLUMN IF NOT EXISTS details TEXT DEFAULT NULL
        ");

        // Keep old databases compatible with the current app shape.
        self::runSchemaStatement($pdo, "
            ALTER TABLE integrations
              ADD COLUMN IF NOT EXISTS vendor_name VARCHAR(120) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS integration_profile VARCHAR(80) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS tool_category ENUM('sast','dast','sca','mobile','pentest','assistant','automation') NOT NULL DEFAULT 'automation',
              ADD COLUMN IF NOT EXISTS connection_type ENUM('docker','api','python','manual') NOT NULL DEFAULT 'manual',
              ADD COLUMN IF NOT EXISTS endpoint_url VARCHAR(255) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS api_base_url VARCHAR(255) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS scan_submit_url VARCHAR(255) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS result_url VARCHAR(255) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS auth_type VARCHAR(40) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS documentation_url VARCHAR(255) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS last_tested_at DATETIME DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS last_test_status ENUM('unknown','up','down','partial') NOT NULL DEFAULT 'unknown',
              ADD COLUMN IF NOT EXISTS last_test_detail VARCHAR(255) DEFAULT NULL,
              ADD COLUMN IF NOT EXISTS tool_logo_path VARCHAR(255) DEFAULT NULL
        ");
    }

    private static function runSchemaStatement(PDO $pdo, string $sql): void
    {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // Never block page rendering if migration cannot run in the current environment.
        }
    }
}
