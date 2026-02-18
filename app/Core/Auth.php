<?php

namespace App\Core;

class Auth
{
    private static $user;

    public static function setUser($user)
    {
        self::$user = $user;
    }

    public static function getUser()
    {
        return self::$user;
    }
}