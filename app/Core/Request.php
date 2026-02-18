<?php
namespace App\Core;

class Request
{
    public static function json(): array
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

        if (!str_contains($contentType, 'application/json')) {
            return [];
        }

        $raw = file_get_contents("php://input");
        return json_decode($raw, true) ?? [];
    }

    public static function form(): array
    {
        return $_POST ?? [];
    }

    public static function files(): array
    {
        return $_FILES ?? [];
    }

    public static function input(string $key, $default = null)
    {
        // Priority: JSON → POST
        $json = self::json();
        if (isset($json[$key])) {
            return $json[$key];
        }

        if (isset($_POST[$key])) {
            return $_POST[$key];
        }

        return $default;
    }

    public static function hasFile(string $key): bool
    {
        return isset($_FILES[$key]) && $_FILES[$key]['error'] === UPLOAD_ERR_OK;
    }

    public static function file(string $key): ?array
    {
        return self::hasFile($key) ? $_FILES[$key] : null;
    }
}
