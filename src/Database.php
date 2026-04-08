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
            return new PDO(
                "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4",
                $user,
                $pass,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ]
            );
        } catch (Throwable $e) {
            return null;
        }
    }
}
