<?php
namespace App\Core;

class AdminAuth
{
    private static ?array $admin = null;

    public static function setAdmin(array $admin): void
    {
        self::$admin = $admin;
    }

    public static function admin(): ?array
    {
        return self::$admin;
    }
}