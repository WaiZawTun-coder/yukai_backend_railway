<?php
namespace App\Core;

use Exception;

class JWT
{
    /* ===============================
       Base64 URL helpers
    =============================== */

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /* ===============================
       Encode JWT
    =============================== */

    public static function encode(array $payload, string $secret, int $expiresIn): string
    {
        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];

        $now = time();

        $payload = array_merge($payload, [
            'iat' => $now,
            'exp' => $now + $expiresIn
        ]);

        $base64Header = self::base64UrlEncode(json_encode($header));
        $base64Payload = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac(
            'sha256',
            $base64Header . '.' . $base64Payload,
            $secret,
            true
        );

        return $base64Header . '.' . $base64Payload . '.' . self::base64UrlEncode($signature);
    }

    /* ===============================
       Decode & Verify JWT
    =============================== */

    public static function decode(string $token, string $secret): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception('Malformed token');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $expectedSignature = self::base64UrlEncode(
            hash_hmac(
                'sha256',
                $headerB64 . '.' . $payloadB64,
                $secret,
                true
            )
        );

        if (!hash_equals($expectedSignature, $signatureB64)) {
            throw new Exception('Invalid token signature');
        }

        $payload = json_decode(self::base64UrlDecode($payloadB64), true);

        if (!$payload) {
            throw new Exception('Invalid payload');
        }

        if (!isset($payload['exp']) || time() >= $payload['exp']) {
            throw new Exception('Token expired');
        }

        return $payload;
    }
}

