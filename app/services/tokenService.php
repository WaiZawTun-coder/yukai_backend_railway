<?php
namespace App\Service;

use App\Core\JWT;

class TokenService
{
    /* ===============================
       Access Token (JWT)
    =============================== */

    public static function generateAccessToken(
        array $payload,
        int $ttl = 1800
    ): string {
        return JWT::encode(
            $payload,
            $_ENV['JWT_SECRET'],
            $ttl
        );
    }

    public static function verifyAccessToken(string $token): ?array
    {
        try {
            return JWT::decode($token, $_ENV['JWT_SECRET']);
        } catch (\Exception $e) {
            return null;
        }
    }

    /* ===============================
       Refresh Token
    =============================== */

    public static function generateRefreshToken(): array
    {
        $token = bin2hex(random_bytes(32));
        $hash = hash('sha256', $token);

        return [
            'token' => $token,
            'hash' => $hash
        ];
    }

    public static function verifyRefreshToken(string $token, string $storedHash): bool
    {
        return hash_equals($storedHash, hash('sha256', $token));
    }
}
