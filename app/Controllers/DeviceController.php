<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class DeviceController
{
    public static function registerDevice()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $input = Request::json();

        /* ---------------- VALIDATION ---------------- */

        $required = [
            "device_id",
            "identity_key_pub",
            "signed_prekey_pub",
            "signed_prekey_sig",
            "signed_prekey_id",
            "registration_id"
        ];

        foreach ($required as $field) {
            if (!isset($input[$field])) {
                Response::json([
                    "status" => false,
                    "message" => "Missing field: $field"
                ], 400);
                return;
            }
        }

        /* ---------------- INPUT ---------------- */

        $deviceId = (string) $input["device_id"];
        $deviceName = $input["device_name"] ?? null;
        $platform = $input["platform"] ?? null;

        // 🔐 IMPORTANT: keep as STRING
        $signedPreKeyId = (string) $input["signed_prekey_id"];
        $registrationId = (int) $input["registration_id"];

        /* ---------------- BASE64 → BINARY ---------------- */

        $identityKeyPub = base64_decode($input["identity_key_pub"], true);
        $signedPreKeyPub = base64_decode($input["signed_prekey_pub"], true);
        $signedPreKeySig = base64_decode($input["signed_prekey_sig"], true);

        if ($identityKeyPub === false) {
            Response::json([
                "status" => false,
                "message" => "Invalid base64 key data identityKeyPub"
            ], 400);
            return;
        }

        if ($signedPreKeyPub === false) {
            Response::json([
                "status" => false,
                "message" => "Invalid base64 key data signedPreKeyPub"
            ], 400);
            return;
        }

        if ($signedPreKeySig === false) {
            Response::json([
                "status" => false,
                "message" => "Invalid base64 key data signedPreKeySig"
            ], 400);
            return;
        }

        $isTrusted = 0;
        $isActive = 1;

        /* ---------------- SQL ---------------- */

        $sql = "
        INSERT INTO devices (
            user_id,
            device_id,
            device_name,
            platform,
            identity_key_pub,
            signed_prekey_pub,
            signed_prekey_sig,
            signed_prekey_id,
            registration_id,
            is_trusted,
            is_active,
            last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE
            signed_prekey_pub = VALUES(signed_prekey_pub),
            signed_prekey_sig = VALUES(signed_prekey_sig),
            signed_prekey_id  = VALUES(signed_prekey_id),
            registration_id   = VALUES(registration_id),
            is_active         = 1,
            last_seen_at      = NOW()
    ";

        $stmt = $conn->prepare($sql);

        // i s s s b b b s i i i
        $stmt->bind_param(
            "isssbbbsiii",
            $me,
            $deviceId,
            $deviceName,
            $platform,
            $identityKeyPub,
            $signedPreKeyPub,
            $signedPreKeySig,
            $signedPreKeyId,
            $registrationId,
            $isTrusted,
            $isActive
        );

        // BLOBs (0-based index)
        $stmt->send_long_data(4, $identityKeyPub);
        $stmt->send_long_data(5, $signedPreKeyPub);
        $stmt->send_long_data(6, $signedPreKeySig);

        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Device registration successful"
        ]);
    }



    public static function getPublicKeys()
    {
        $conn = Database::connect();
        $user_id = $_GET["user_id"] ?? null;

        if (!$user_id) {
            Response::json([
                "status" => false,
                "message" => "Missing user_id"
            ], 400);
        }

        $sql = "SELECT
                    device_id,
                    identity_key_pub,
                    signed_prekey_pub,
                    signed_prekey_sig,
                    signed_prekey_id,
                    is_trusted,
                    platform
                FROM devices
                WHERE user_id = ?
                    AND is_active = TRUE";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);

        $stmt->execute();

        $result = $stmt->get_result();

        $keys = [];

        while ($row = $result->fetch_assoc()) {
            $keys[] = [
                "device_id" => $row["device_id"],

                "identity_key_pub" => base64_encode($row["identity_key_pub"]),
                "signed_prekey_pub" => base64_encode($row["signed_prekey_pub"]),
                "signed_prekey_sig" => base64_encode($row["signed_prekey_sig"]),

                "signed_prekey_id" => (int) $row["signed_prekey_id"],

                "is_trusted" => (bool) $row["is_trusted"],
                "platform" => $row["platform"],
            ];
        }

        Response::json([
            "status" => true,
            "data" => $keys
        ]);
    }

    public static function getDeviceStatus()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $device_id = trim($_GET["device_id"] ?? "");
        if ($device_id === "") {
            Response::json([
                "status" => false,
                "message" => "Device ID is required."
            ]);
            return;
        }

        $sql = "SELECT device_id, identity_key_pub FROM devices WHERE device_id=? AND user_id=? AND is_active = TRUE LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $device_id, $me);
        $stmt->execute();
        $result = $stmt->get_result();

        $count = $result->num_rows;
        if ($count == 0) {
            Response::json([
                "status" => true,
                "has_keys" => false
            ]);
            return;
        }

        Response::json([
            "status" => true,
            "has_keys" => true
        ]);
    }

    public static function resetDevice()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = $user["user_id"];

        if (!$me) {
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ]);
            return;
        }

        $sql = "DELETE FROM devices WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $me);

        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Device reset successful"
        ]);
        return;
    }
}