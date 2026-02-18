<?php


namespace App\Controllers;


use App\Core\Auth;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class MessageController
{
    /**
     * Get messages of a chat (with pagination)
     */
    public static function getMessages()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = (int) $user["user_id"];

        $chat_id = (int) ($_GET["chat_id"] ?? 0);
        $device_id = $_GET["device_id"] ?? null;
        $page = max(1, (int) ($_GET["page"] ?? 1));
        $limit = 30;
        $offset = ($page - 1) * $limit;

        if (!$chat_id || !$device_id) {
            Response::json([
                "status" => false,
                "message" => "chat_id and device_id required"
            ]);
            return;
        }

        // ✅ Security: ensure user is participant
        $check = $conn->prepare("
            SELECT 1 
            FROM chat_participants 
            WHERE chat_id=? AND user_id=? 
            LIMIT 1
        ");
        $check->bind_param("ii", $chat_id, $user_id);
        $check->execute();

        if (!$check->get_result()->fetch_row()) {
            Response::json([
                "status" => false,
                "message" => "Access denied"
            ]);
            return;
        }

        /**
         * ✅ Fetch messages with per-device encrypted payload
         * Sender messages will appear with NULL payload (if sender payloads not stored).
         */
        $sql = "SELECT
                    m.message_id,
                    m.chat_id,
                    m.sender_user_id,
                    m.message_type,
                    m.reply_to_message_id,
                    m.sent_at,
                    m.is_edited,
                    m.is_deleted,

                    u.username,
                    u.display_name,
                    u.profile_image,
                    u.gender,

                    -- Payload for THIS device only (decrypt)
                    mpd.cipher_text,
                    mpd.iv,
                    mpd.signed_prekey_id,
                    mpd.sender_signed_prekey_pub,

                    -- Aggregated status
                    CASE
                        WHEN SUM(mpa.status = 'seen') > 0 THEN 'seen'
                        WHEN SUM(mpa.status IN ('delivered','seen')) > 0 THEN 'delivered'
                        ELSE 'sent'
                    END AS status

                    FROM messages m
                    JOIN users u
                        ON u.user_id = m.sender_user_id
                        
                    LEFT JOIN message_payloads mpd
                        ON mpd.message_id = m.message_id
                       AND mpd.recipient_user_id = ?
                       AND mpd.recipient_device_id = ?
                        
                    -- Payloads for ALL recipients (status aggregation)
                    LEFT JOIN message_payloads mpa
                        ON mpa.message_id = m.message_id
                        
                    WHERE m.chat_id = ?
                        
                    GROUP BY
                        m.message_id,
                        mpd.cipher_text,
                        mpd.iv,
                        mpd.signed_prekey_id,
                        mpd.sender_signed_prekey_pub
                        
                    ORDER BY m.sent_at DESC
                    LIMIT ? OFFSET ?";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param(
            "isiii",
            $user_id,
            $device_id,
            $chat_id,
            $limit,
            $offset
        );

        $stmt->execute();
        $result = $stmt->get_result();

        $messages = [];
        while ($row = $result->fetch_assoc()) {
            $messages[] = $row;
        }

        Response::json([
            "status" => true,
            "page" => $page,
            "limit" => $limit,
            "data" => array_reverse($messages)
        ]);
    }

    /**
     * Send a message (E2EE, multi-device)
     */
    public static function sendMessage()
    {
        $conn = Database::connect();
        $conn->begin_transaction();

        try {
            $user = Auth::getUser();
            $user_id = (int) $user["user_id"];

            $input = Request::json();

            $chat_id = (int) ($input["chat_id"] ?? 0);
            $payloads = $input["payloads"] ?? [];
            $message_type = $input["message_type"] ?? "text";
            $reply_to = isset($input["reply_to_message_id"])
                ? (int) $input["reply_to_message_id"]
                : null;

            if (!$chat_id || empty($payloads) || !is_array($payloads)) {
                throw new \Exception("chat_id and payloads required");
            }

            // ✅ Verify sender is participant
            $check = $conn->prepare("
            SELECT 1
            FROM chat_participants
            WHERE chat_id = ? AND user_id = ?
            LIMIT 1
        ");
            $check->bind_param("ii", $chat_id, $user_id);
            $check->execute();

            if (!$check->get_result()->fetch_row()) {
                throw new \Exception("Access denied");
            }

            // ✅ Insert message metadata (NO plaintext)
            $stmt = $conn->prepare("
            INSERT INTO messages
                (chat_id, sender_user_id, message_type, reply_to_message_id)
            VALUES (?, ?, ?, ?)
        ");
            $stmt->bind_param("iisi", $chat_id, $user_id, $message_type, $reply_to);
            $stmt->execute();

            $message_id = $stmt->insert_id;

            // ✅ Insert per-device encrypted payloads
            $stmtPayload = $conn->prepare("
            INSERT INTO message_payloads
                (message_id, recipient_user_id, recipient_device_id, cipher_text, iv, signed_prekey_id, sender_signed_prekey_pub)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");

            $hasSelfPayload = false;

            foreach ($payloads as $p) {
                if (
                    empty($p["recipient_user_id"]) ||
                    empty($p["recipient_device_id"]) ||
                    empty($p["cipher_text"]) ||
                    empty($p["iv"])
                ) {
                    throw new \Exception("Invalid payload format");
                }

                $recipient_user_id = (int) $p["recipient_user_id"];
                $recipient_device_id = (string) $p["recipient_device_id"];
                $cipher_text = (string) $p["cipher_text"];
                $iv = (string) $p["iv"];
                $signed_prekey_id = (int) ($p["signed_prekey_id"] ?? 0);

                if ($recipient_user_id === $user_id) {
                    $hasSelfPayload = true;
                }

                $sender_signed_prekey_pub = $p["sender_signed_prekey_pub"] ?? null;
                if (!$sender_signed_prekey_pub) {
                    throw new \Exception("Missing sender signed prekey");
                }

                $stmtPayload->bind_param(
                    "iisssis",
                    $message_id,
                    $recipient_user_id,
                    $recipient_device_id,
                    $cipher_text,
                    $iv,
                    $signed_prekey_id,
                    $sender_signed_prekey_pub
                );


                // $stmtPayload->bind_param(
                //     "iisssi",
                //     $message_id,
                //     $recipient_user_id,
                //     $recipient_device_id,
                //     $cipher_text,
                //     $iv,
                //     $signed_prekey_id
                // );
                $stmtPayload->execute();
            }

            // ✅ Enforce sender device payload (VERY IMPORTANT)
            if (!$hasSelfPayload) {
                throw new \Exception("Missing encrypted payload for sender device");
            }

            $conn->commit();

            Response::json([
                "status" => true,
                "message" => "Message sent",
                "message_id" => $message_id
            ]);

        } catch (\Throwable $e) {
            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => $e->getMessage()
            ]);
        }
    }


    /**
     * Edit a message (replaces encrypted payloads)
     */
    public static function editMessage()
    {
        $conn = Database::connect();
        $conn->begin_transaction();

        try {
            $user = Auth::getUser();
            $user_id = (int) $user["user_id"];
            $input = Request::json();

            $message_id = (int) ($input["message_id"] ?? 0);
            $payloads = $input["payloads"] ?? [];

            if (!$message_id || empty($payloads)) {
                throw new \Exception("message_id and payloads required");
            }

            // ✅ Verify ownership
            $check = $conn->prepare("
                SELECT 1 
                FROM messages 
                WHERE message_id=? AND sender_user_id=? 
                LIMIT 1
            ");
            $check->bind_param("ii", $message_id, $user_id);
            $check->execute();
            if (!$check->get_result()->fetch_row()) {
                throw new \Exception("Access denied");
            }

            // ✅ Mark edited
            $stmt = $conn->prepare("
                UPDATE messages 
                SET is_edited=1 
                WHERE message_id=?
            ");
            $stmt->bind_param("i", $message_id);
            $stmt->execute();

            // ✅ Remove old payloads
            $del = $conn->prepare("
                DELETE FROM message_payloads 
                WHERE message_id=?
            ");
            $del->bind_param("i", $message_id);
            $del->execute();

            // ✅ Insert new payloads
            $stmtPayload = $conn->prepare("
                INSERT INTO message_payloads
                    (message_id, recipient_user_id, recipient_device_id, cipher_text, iv, signed_prekey_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ");

            foreach ($payloads as $p) {
                $stmtPayload->bind_param(
                    "iisssi",
                    $message_id,
                    $p['recipient_user_id'],
                    $p['recipient_device_id'],
                    $p['cipher_text'],
                    $p['iv'],
                    $p['signed_prekey_id']
                );
                $stmtPayload->execute();
            }

            $conn->commit();

            Response::json([
                "status" => true,
                "message" => "Message edited"
            ]);

        } catch (\Throwable $e) {
            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => $e->getMessage()
            ]);
        }
    }

    /**
     * Delete a message (soft delete)
     */
    public static function deleteMessage()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = (int) $user["user_id"];
        $input = Request::json();

        $message_id = (int) ($input["message_id"] ?? 0);

        if (!$message_id) {
            Response::json([
                "status" => false,
                "message" => "message_id required"
            ]);
            return;
        }

        $stmt = $conn->prepare("
            UPDATE messages 
            SET is_deleted=1 
            WHERE message_id=? AND sender_user_id=?
        ");
        $stmt->bind_param("ii", $message_id, $user_id);
        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Message deleted"
        ]);
    }

    /**
     * Update message receipt status (seen / delivered)
     */
    public static function updateReceipt()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = (int) $user["user_id"];
        $input = Request::json();

        // $chat_id = (int) ($input["chat_id"] ?? 0);
        $message_id = (int) ($input["message_id"] ?? 0);
        $status = $input["status"] ?? 'sent';

        if (!$message_id || !in_array($status, ['delivered', 'seen'])) {
            Response::json([
                "status" => false,
                "message" => "Invalid input"
            ]);
            return;
        }

        // ✅ Update messages sent by others in this chat
        $stmt = $conn->prepare("
            UPDATE message_payloads
            SET status=? 
            WHERE message_id=? 
              AND recipient_user_id=? 
              AND status!='seen'
        ");
        $stmt->bind_param("sii", $status, $message_id, $user_id);
        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Receipt updated"
        ]);
    }
}
