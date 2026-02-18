<?php


namespace App\Controllers;


use App\Core\Auth;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use mysqli_sql_exception;

class ChatController
{
    /* ============================
        GET MY CHAT LIST
       ============================ */
    public static function getMyChats()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = (int) $user["user_id"];
        $device_id = $_GET["device_id"] ?? null;

        if (!$device_id) {
            Response::json(["status" => false, "message" => "device_id required"], 400);
            return;
        }

        // Fetch chats with last message and unread count
        $sql = "
               SELECT 
                   c.chat_id,
                   c.type,
                   c.created_at,
                c.chat_name,
       
                   -- Last message info
                   m.message_id AS last_message_id,
                   m.sender_user_id AS last_message_sender_id,
                   m.message_type AS last_message_type,
                   m.reply_to_message_id AS last_message_reply_to,
                   m.sent_at AS last_message_time,
                   m.is_edited AS last_message_edited,
                   m.is_deleted AS last_message_deleted,
       
                   mp.cipher_text AS last_message_cipher_text,
                   mp.iv AS last_message_iv,
                   mp.signed_prekey_id AS last_message_signed_prekey_id,
                   mp.sender_signed_prekey_pub AS last_message_sender_signed_prekey_pub,
                   mp.status AS last_message_status,
       
                   last_sender.username AS last_sender_username,
                   last_sender.display_name AS last_sender_name,
                   last_sender.profile_image AS last_sender_profile_image,
       
                   -- Unread count for this user/device
                   (
                       SELECT COUNT(*)
                       FROM messages um
                       JOIN message_payloads ump 
                         ON ump.message_id = um.message_id
                        AND ump.recipient_user_id = ?
                        AND ump.recipient_device_id = ?
                       WHERE um.chat_id = c.chat_id
                         AND um.sender_user_id != ?
                         AND um.is_deleted = 0
                         AND ump.status != 'seen'
                   ) AS unread_count
       
               FROM chat_participants cp
               JOIN chats c ON c.chat_id = cp.chat_id
       
               LEFT JOIN messages m
                 ON m.message_id = (
                     SELECT m2.message_id
                     FROM messages m2
                     WHERE m2.chat_id = c.chat_id
                       AND m2.is_deleted = 0
                     ORDER BY m2.sent_at DESC
                     LIMIT 1
                 )
       
               LEFT JOIN message_payloads mp
                 ON mp.message_id = m.message_id
                AND mp.recipient_device_id = ?
       
               LEFT JOIN users last_sender
                 ON last_sender.user_id = m.sender_user_id
       
               WHERE cp.user_id = ?
               ORDER BY m.sent_at DESC, c.created_at DESC
           ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param(
            "isisi",
            $user_id,     // unread_count recipient_user_id
            $device_id,   // unread_count recipient_device_id
            $user_id,     // unread_count sender_user_id !=
            // $user_id,     // mp.recipient_user_id
            $device_id,   // mp.recipient_device_id
            $user_id      // cp.user_id
        );

        $stmt->execute();
        $res = $stmt->get_result();

        $chats = [];
        $chat_ids = [];

        while ($row = $res->fetch_assoc()) {
            $chat_id = $row["chat_id"];
            $chats[$chat_id] = $row;
            $chat_ids[] = $chat_id;
            $chats[$chat_id]["participants"] = []; // initialize participants array
        }

        // Fetch participants excluding current user
        if (!empty($chat_ids)) {
            $ids_placeholders = implode(',', array_fill(0, count($chat_ids), '?'));
            $types = str_repeat('i', count($chat_ids)) . 'i'; // extra 'i' for current user exclusion
            $params = array_merge($chat_ids, [$user_id]);

            $sql2 = "
                   SELECT cp.chat_id, u.user_id, u.display_name, u.profile_image, u.gender, u.username
                   FROM chat_participants cp
                   JOIN users u ON u.user_id = cp.user_id
                   WHERE cp.chat_id IN ($ids_placeholders)
                     AND cp.user_id != ?
               ";

            $stmt2 = $conn->prepare($sql2);
            $stmt2->bind_param($types, ...$params);
            $stmt2->execute();
            $res2 = $stmt2->get_result();

            while ($p = $res2->fetch_assoc()) {
                $chats[$p["chat_id"]]["participants"][] = [
                    "user_id" => $p["user_id"],
                    "display_name" => $p["display_name"],
                    "profile_image" => $p["profile_image"],
                    "gender" => $p["gender"],
                    "username" => $p["username"]
                ];
            }
        }

        Response::json([
            "status" => true,
            "data" => array_values($chats)
        ]);
    }

    /* ============================
        GET PRIVATE CHAT
       ============================ */
    public static function getChat()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $username = trim($_GET["username"] ?? "");
        $device_id = $_GET["device_id"] ?? '';

        if (!$username) {
            Response::json(["status" => false, "message" => "Username required"], 400);
            return;
        }

        if (!$device_id) {
            Response::json(["status" => false, "message" => "device_id required"], 400);
            return;
        }

        // Find target user
        $userStmt = $conn->prepare("
               SELECT user_id, username, display_name, profile_image, gender
               FROM users
               WHERE username = ?
               LIMIT 1
           ");
        $userStmt->bind_param("s", $username);
        $userStmt->execute();
        $target = $userStmt->get_result()->fetch_assoc();

        // Check if blocked either way
$blockStmt = $conn->prepare("
    SELECT 1 
    FROM blocks
    WHERE 
        (blocker_user_id = ? AND blocked_user_id = ?)
        OR
        (blocker_user_id = ? AND blocked_user_id = ?)
    LIMIT 1
");
$blockStmt->bind_param(
    "iiii",
    $me,           // I blocked
    $target["user_id"],
    $target["user_id"], // They blocked me
    $me
);
$blockStmt->execute();

if ($blockStmt->get_result()->fetch_row()) {
    Response::json([
        "status" => false,
        "message" => "Cannot chat with this user"
    ], 403);
    return;
}


        if (!$target) {
            Response::json(["status" => false, "message" => "User not found"], 404);
            return;
        }

        $other_user_id = (int) $target["user_id"];

        // Prevent self-chat
        if ($other_user_id === $me) {
            Response::json(["status" => false, "message" => "Cannot chat with yourself"], 400);
            return;
        }

        // Find private chat between both users
        $chatStmt = $conn->prepare("
               SELECT c.chat_id
               FROM chats c
               JOIN chat_participants p1 ON p1.chat_id = c.chat_id AND p1.user_id = ?
               JOIN chat_participants p2 ON p2.chat_id = c.chat_id AND p2.user_id = ?
               WHERE c.type = 'private'
               LIMIT 1
           ");
        $chatStmt->bind_param("ii", $me, $other_user_id);
        $chatStmt->execute();
        $chatRow = $chatStmt->get_result()->fetch_assoc();

        /* -------------------- Auto-create chat -------------------- */
        if (!$chatRow) {

            $conn->begin_transaction();

            try {
                // Create chat
                $createChatStmt = $conn->prepare("
            INSERT INTO chats (type, created_by_user_id, created_at)
            VALUES ('private', ?, NOW())
        ");
                $createChatStmt->bind_param("i", $me);
                $createChatStmt->execute();
                $chat_id = $conn->insert_id;

                // Add participants
                $participantStmt = $conn->prepare("
            INSERT INTO chat_participants (chat_id, user_id)
            VALUES (?, ?)
        ");

                $participantStmt->bind_param("ii", $chat_id, $me);
                $participantStmt->execute();

                $participantStmt->bind_param("ii", $chat_id, $other_user_id);
                $participantStmt->execute();

                $conn->commit();

            } catch (\Throwable $e) {
                $conn->rollback();

                Response::json([
                    "status" => false,
                    "message" => "Failed to create chat",
                    "detail" => $e->getMessage()
                ], 500);
                return;
            }

        } else {
            $chat_id = (int) $chatRow["chat_id"];
        }

        // Load chat info
        $sql = "
              SELECT 
                  c.chat_id,
                  c.type,
                  c.created_at,
                  c.chat_name,
       
                  u.user_id AS other_user_id,
                  u.username AS other_username,
                  u.display_name AS other_display_name,
                  u.profile_image AS other_profile_image,
                  u.gender AS other_gender,
       
                  (SELECT COUNT(*) 
                   FROM chat_participants p 
                   WHERE p.chat_id = c.chat_id
                  ) AS member_count,
       
                  m.message_id AS last_message_id,
                  mp.cipher_text AS last_message,
                  m.message_type AS last_message_type,
                  m.sent_at AS last_message_time,
                  m.sender_user_id AS last_message_sender_id,
                  mp.status AS last_message_status,
       
                  last_sender.display_name AS last_sender_name,
       
                  (
                      SELECT COUNT(*)
                      FROM messages um
                      JOIN message_payloads ump ON ump.message_id = um.message_id
                      WHERE um.chat_id = c.chat_id
                        AND um.sender_user_id != ?
                        AND ump.recipient_user_id = ?
                        AND ump.status != 'seen'
                        AND um.is_deleted = 0
                  ) AS unread_count
       
              FROM chats c
       
              JOIN chat_participants cp 
                ON cp.chat_id = c.chat_id 
               AND cp.user_id = ?
       
              LEFT JOIN chat_participants cp2
                ON cp2.chat_id = c.chat_id
               AND cp2.user_id != cp.user_id
       
              LEFT JOIN users u 
                ON u.user_id = cp2.user_id
       
              LEFT JOIN messages m 
                ON m.message_id = (
                    SELECT m2.message_id 
                    FROM messages m2
                    WHERE m2.chat_id = c.chat_id
                      AND m2.is_deleted = 0
                    ORDER BY m2.sent_at DESC
                    LIMIT 1
                )
       
              LEFT JOIN message_payloads mp
                ON mp.message_id = m.message_id
               AND mp.recipient_user_id = ?
               AND mp.recipient_device_id = ?
       
              LEFT JOIN users last_sender 
                ON last_sender.user_id = m.sender_user_id
       
              WHERE c.chat_id = ?
              LIMIT 1
           ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param(
            "iiissi",
            $me,
            $me,
            $me,
            $me,
            $device_id,
            $chat_id
        );
        $stmt->execute();
        $chat = $stmt->get_result()->fetch_assoc();

        Response::json([
            "status" => true,
            "data" => $chat,
            "can_create" => false,
            "target_user" => $target
        ]);
    }

    public static function getChatById()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $chatId = (int) trim($_GET["chat_id"] ?? "");
        if (!$chatId) {
            Response::json(["status" => false, "message" => "Invalid Chat Id"], 400);
            return;
        }

        $device_id = trim($_GET["device_id"] ?? "");
        if (!$device_id) {
            Response::json(["status" => false, "message" => "device_id required"], 400);
            return;
        }

        // Removed echo to avoid corrupting JSON response

        $sql = "SELECT 
              c.chat_id,
              c.type,
              c.created_at,
              c.chat_name,
   
              u.user_id AS other_user_id,
              u.username AS other_username,
              u.display_name AS other_display_name,
              u.profile_image AS other_profile_image,
              u.gender AS other_gender,
   
              (SELECT COUNT(*) 
               FROM chat_participants p 
               WHERE p.chat_id = c.chat_id
              ) AS member_count,
   
              m.message_id AS last_message_id,
              mp.cipher_text AS last_message,
              m.message_type AS last_message_type,
              m.sent_at AS last_message_time,
              m.sender_user_id AS last_message_sender_id,
              mp.status AS last_message_status,
   
              last_sender.display_name AS last_sender_name,
   
              (
                  SELECT COUNT(*)
                  FROM messages um
                  JOIN message_payloads ump ON ump.message_id = um.message_id
                  WHERE um.chat_id = c.chat_id
                    AND um.sender_user_id != ?
                    AND ump.recipient_user_id = ?
                    AND ump.status != 'seen'
                    AND um.is_deleted = 0
              ) AS unread_count
   
          FROM chats c
   
          JOIN chat_participants cp 
            ON cp.chat_id = c.chat_id 
           AND cp.user_id = ?
   
          LEFT JOIN chat_participants cp2
            ON cp2.chat_id = c.chat_id
           AND cp2.user_id != cp.user_id
   
          LEFT JOIN users u 
            ON u.user_id = cp2.user_id
   
          LEFT JOIN messages m 
            ON m.message_id = (
                SELECT m2.message_id 
                FROM messages m2
                WHERE m2.chat_id = c.chat_id
                  AND m2.is_deleted = 0
                ORDER BY m2.sent_at DESC
                LIMIT 1
            )
   
          LEFT JOIN message_payloads mp
            ON mp.message_id = m.message_id
           AND mp.recipient_user_id = ?
           AND mp.recipient_device_id = ?
   
          LEFT JOIN users last_sender 
            ON last_sender.user_id = m.sender_user_id
   
          WHERE c.chat_id = ?
          LIMIT 1";

        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            Response::json(["status" => false, "message" => "SQL prepare failed: " . $conn->error], 500);
            return;
        }

        $stmt->bind_param("iiiisi", $me, $me, $me, $me, $device_id, $chatId);
        if (!$stmt->execute()) {
            Response::json(["status" => false, "message" => "SQL execute failed: " . $stmt->error], 500);
            return;
        }

        $result = $stmt->get_result();
        if (!$result) {
            Response::json(["status" => false, "message" => "SQL get_result failed: " . $stmt->error], 500);
            return;
        }

        $chat = $result->fetch_assoc();
        $stmt->close();

        if (!$chat) {
            Response::json(["status" => false, "message" => "Chat not found or no access"], 404);
            return;
        }

        Response::json(["status" => true, "data" => $chat, "can_create" => false]);
    }



    /* ============================
        CREATE OR GET PRIVATE CHAT
       ============================ */
    public static function createPrivateChat()
    {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];
        $target_id = (int) Request::input("target_user_id");

        if (!$target_id || $target_id == $me) {
            Response::json(["status" => false, "message" => "Invalid target user"], 400);
            return;
        }

        // Check existing chat
        $checkSql = "
            SELECT c.chat_id
            FROM chats c
            JOIN chat_participants a ON a.chat_id = c.chat_id
            JOIN chat_participants b ON b.chat_id = c.chat_id
            WHERE c.type = 'private'
              AND a.user_id = ?
              AND b.user_id = ?
            LIMIT 1
        ";

        $stmt = $conn->prepare($checkSql);
        $stmt->bind_param("ii", $me, $target_id);
        $stmt->execute();
        $existing = $stmt->get_result()->fetch_assoc();

        if ($existing) {
            Response::json(["status" => true, "chat_id" => $existing["chat_id"], "is_new" => false]);
            return;
        }

        $conn->begin_transaction();
        try {
            $stmt = $conn->prepare("INSERT INTO chats (type, created_by_user_id) VALUES ('private', ?)");
            $stmt->bind_param("i", $me);
            $stmt->execute();
            $chat_id = $stmt->insert_id;

            $stmt = $conn->prepare("INSERT INTO chat_participants (chat_id, user_id) VALUES (?, ?)");
            $stmt->bind_param("ii", $chat_id, $me);
            $stmt->execute();
            $stmt->bind_param("ii", $chat_id, $target_id);
            $stmt->execute();

            $conn->commit();

            Response::json(["status" => true, "chat_id" => $chat_id, "is_new" => true]);
        } catch (mysqli_sql_exception $e) {
            $conn->rollback();
            Response::json(["status" => false, "message" => "Failed to create chat", "error" => $e->getMessage()], 500);
        }
    }

    /* ============================
        CREATE GROUP CHAT
       ============================ */
    public static function createGroupChat()
    {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $chat_name = Request::input("chat_name");

        $members = Request::input("members");
        if (!is_array($members) || count($members) == 0) {
            Response::json(["status" => false, "message" => "Members required"], 400);
            return;
        }

        $conn->begin_transaction();
        try {
            $stmt = $conn->prepare("INSERT INTO chats (type,chat_name, created_by_user_id) VALUES ('group',?, ?)");
            $stmt->bind_param("si", $chat_name, $me);
            $stmt->execute();
            $chat_id = $stmt->insert_id;

            $insert = $conn->prepare("INSERT INTO chat_participants (chat_id, user_id) VALUES (?, ?)");
            $insert->bind_param("ii", $chat_id, $me);
            $insert->execute();

            foreach ($members as $uid) {
                $uid = (int) $uid;
                if ($uid == $me)
                    continue;
                $insert->bind_param("ii", $chat_id, $uid);
                $insert->execute();
            }

            $conn->commit();
            Response::json(["status" => true, "chat_id" => $chat_id]);
        } catch (mysqli_sql_exception $e) {
            $conn->rollback();
            Response::json(["status" => false, "message" => "Failed to create group", "error" => $e->getMessage()], 500);
        }
    }

    public static function addParticipants()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $input = Request::json();

        $chat_id = (int) $input["chat_id"];
        $members = $input["members"];
        if (!is_array($members) || count($members) == 0) {
            Response::json(["status" => false, "message" => "Members required"]);
            return;
        }

        $sql = "INSERT INTO chat_participants (chat_id, user_id) VALUES (?, ?)";
        $stmt = $conn->prepare($sql);

        foreach ($members as $uid) {
            $uid = (int) $uid;
            if ($uid == $me)
                continue;
            $stmt->bind_param("ii", $chat_id, $uid);
            $stmt->execute();
        }

        Response::json(["status" => true, "message" => "Successfully add new members"]);

    }

    /* ============================
        GET CHAT PARTICIPANTS
       ============================ */
    public static function getParticipants()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];
        $chat_id = (int) ($_GET["chat_id"] ?? 0);
        $device_id = $_GET["device_id"] ?? null;

        if (!$chat_id || !$device_id) {
            Response::json([
                "status" => false,
                "message" => "chat_id and device_id required"
            ], 400);
            return;
        }

        $check = $conn->prepare("SELECT 1 FROM chat_participants WHERE chat_id = ? AND user_id = ?");
        $check->bind_param("ii", $chat_id, $me);
        $check->execute();
        if (!$check->get_result()->num_rows) {
            Response::json(["status" => false, "message" => "Access denied"], 403);
            return;
        }

        $sql = "
           SELECT 
               u.user_id,
               u.username,
               u.display_name,
               u.profile_image,
               u.gender,
               cp.joined_at,
               cp.is_muted,
               d.device_id,
               d.identity_key_pub,
               d.signed_prekey_pub,
               d.signed_prekey_sig,
               d.signed_prekey_id,
               d.registration_id
           FROM chat_participants cp
           JOIN users u ON u.user_id = cp.user_id
           LEFT JOIN devices d 
             ON d.user_id = u.user_id 
            AND d.is_active = 1
           WHERE cp.chat_id = ?
       ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $chat_id);
        $stmt->execute();
        $res = $stmt->get_result();

        $participants = [];
        while ($row = $res->fetch_assoc()) {
            $uid = $row["user_id"];
            if (!isset($participants[$uid])) {
                $participants[$uid] = [
                    "user_id" => $row["user_id"],
                    "username" => $row["username"],
                    "display_name" => $row["display_name"],
                    "profile_image" => $row["profile_image"],
                    "joined_at" => $row["joined_at"],
                    "gender" => $row["gender"],
                    "devices" => [],
                    "is_muted" => $row["is_muted"]
                ];
            }

            if ($row["device_id"]) {
                $participants[$uid]["devices"][] = [
                    "device_id" => $row["device_id"],
                    "identity_key_pub" => $row["identity_key_pub"] ? base64_encode($row["identity_key_pub"]) : null,
                    "signed_prekey_pub" => $row["signed_prekey_pub"] ? base64_encode($row["signed_prekey_pub"]) : null,
                    "signed_prekey_sig" => $row["signed_prekey_sig"] ? base64_encode($row["signed_prekey_sig"]) : null,
                    "signed_prekey_id" => $row["signed_prekey_id"],
                    "registration_id" => $row["registration_id"]
                ];
            }
        }

        Response::json([
            "status" => true,
            "data" => array_values($participants)
        ]);
    }

    /* ============================
        LEAVE CHAT
       ============================ */
    public static function leaveChat()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];
        $chat_id = (int) Request::input("chat_id");

        $stmt = $conn->prepare("DELETE FROM chat_participants WHERE chat_id = ? AND user_id = ?");
        $stmt->bind_param("ii", $chat_id, $me);
        $stmt->execute();

        if ($stmt->affected_rows === 0) {
            Response::json(["status" => false, "message" => "Chat not found or already left"], 404);
            return;
        }

        Response::json(["status" => true]);
    }

    /* ============================
        DELETE CHAT (OWNER ONLY)
       ============================ */
    public static function deleteChat()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];
        $chat_id = (int) Request::input("chat_id");

        $check = $conn->prepare("SELECT chat_id FROM chats WHERE chat_id = ? AND created_by_user_id = ?");
        $check->bind_param("ii", $chat_id, $me);
        $check->execute();

        if (!$check->get_result()->num_rows) {
            Response::json(["status" => false, "message" => "Only owner can delete chat"], 403);
            return;
        }

        $stmt = $conn->prepare("DELETE FROM chats WHERE chat_id = ?");
        $stmt->bind_param("i", $chat_id);
        $stmt->execute();

        Response::json(["status" => true]);
    }

    public static function muteChat()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = $user["user_id"];

        $is_muted = Request::input("is_muted") ?? 0;
        $chat_id = Request::input("chat_id") ?? 0;

        if (!$chat_id) {
            Response::json(["status" => false, "message" => "Invalid chat id"]);
        }

        $sql = "UPDATE chat_participants SET is_muted = ? WHERE chat_id = ? AND user_id = ?";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iii", $is_muted, $chat_id, $me);

        $stmt->execute();

        $status = $stmt->get_result();

        Response::json([
            "status" => true,
            "message" => "Muted"
        ]);
    }

    public static function getUnreadMessageCount()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];
        $device_id = $_GET["device_id"] ?? null;

        if (!$device_id) {
            Response::json(["status" => false, "message" => "device_id required"], 400);
            return;
        }

        try {
            $sql = "
            SELECT 
                COUNT(*) AS unread_count
            FROM messages m
            JOIN message_payloads mp ON mp.message_id = m.message_id
            WHERE m.sender_user_id != ?
              AND mp.recipient_user_id = ?
              AND mp.recipient_device_id = ?
              AND mp.status != 'seen'
              AND m.is_deleted = 0
        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("iis", $me, $me, $device_id);
            $stmt->execute();

            $result = $stmt->get_result()->fetch_assoc();

            Response::json([
                "status" => true,
                "data" => [
                    "unread_count" => (int) $result["unread_count"]
                ]
            ]);
        } catch (\Throwable $e) {
            Response::json([
                "status" => false,
                "message" => "Failed to get unread message count",
                "detail" => $e->getMessage()
            ], 500);
        }
    }
}
