<?php

declare(strict_types=1);

// ------------------------
// Session
// ------------------------
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ------------------------
// Timezone
// ------------------------
date_default_timezone_set('UTC');

// ------------------------
// Environment Loader (.env)
// ------------------------
$envPath = __DIR__ . '/.env';

if (file_exists($envPath)) {
    foreach (file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);

        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        [$key, $value] = explode('=', $line, 2);

        $value = trim($value);
        $value = trim($value, "\"'"); // remove quotes

        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }
}

// ------------------------
// Security Headers
// ------------------------
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// ------------------------
// Default API Response Type
// ------------------------
header('Content-Type: application/json; charset=utf-8');

// ------------------------
// Core Includes
// ------------------------
require_once __DIR__ . '/app/Core/Router.php';
require_once __DIR__ . '/app/middleware/route_guard.php';

// Optional: simple autoloader
spl_autoload_register(function ($class) {
    $path = __DIR__ . '/' . str_replace('\\', '/', $class) . '.php';
    if (file_exists($path)) {
        require_once $path;
    }
});
