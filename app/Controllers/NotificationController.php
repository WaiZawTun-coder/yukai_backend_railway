<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;

class NotificationController
{
    public static function addNotification()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        $type = trim(Request::input("type"));
        $referenceId = (int) Request::input("referenceId");
        $message = trim(Request::input("message"));
        $target = Request::input("target_user_id");

        // Basic validation
        if (!$type || !$referenceId || !$message || !$target) {
            Response::json([
                "status" => false,
                "message" => "Missing required fields"
            ], 400);
            return;
        }

        // Prevent self-notification
        // if ($me === $target_user_id) {
        //     Response::json([
        //         "status" => false,
        //         "message" => "Cannot notify yourself"
        //     ]);
        //     return;
        // }

        try {
            $conn->begin_transaction();

            // Insert notification event
            $eventSQL = "
            INSERT INTO notification_events 
            (sender_user_id, type, reference_id, message) 
            VALUES (?, ?, ?, ?)
        ";

            foreach ($target as $target_user_id) {
                if ($target == $me)
                    continue;

                $eventStmt = $conn->prepare($eventSQL);
                $eventStmt->bind_param("isis", $me, $type, $referenceId, $message);

                if (!$eventStmt->execute()) {
                    throw new \Exception("Failed to insert notification event");
                }

                $event_id = $eventStmt->insert_id;

                // Insert notification for target user
                $notifSQL = "
            INSERT INTO notifications 
            (user_id, notification_event_id) 
            VALUES (?, ?)
        ";

                $notifStmt = $conn->prepare($notifSQL);
                $notifStmt->bind_param("ii", $target_user_id, $event_id);
                $notifStmt->execute();

                // if (!$notifStmt->execute()) {
                //     throw new \Exception("Failed to insert notification");
                // }
            }

            $conn->commit();

            // Success response
            Response::json([
                "status" => true,
                "message" => "Notification created",
                "data" => [
                    "event_id" => $event_id
                ]
            ]);

        } catch (\Throwable $e) {
            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => "Failed to create notification",
                "detail" => $e->getMessage()
            ], 500);
        }
    }

    public static function getNotifications()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        // ✅ FIX: correct pagination source
        [$page, $limit, $offset] = self::getPagination();

        try {
            // 🔹 Count total
            $countSql = "
            SELECT COUNT(*) AS total
            FROM notifications
            WHERE user_id = ?
        ";

            $countStmt = $conn->prepare($countSql);
            $countStmt->bind_param("i", $me);
            $countStmt->execute();
            $total = (int) $countStmt->get_result()->fetch_assoc()["total"];

            $total_pages = (int) ceil($total / $limit);

            // 🔹 Fetch notifications
            $sql = "
            SELECT
                n.notification_id AS id,
                n.is_read,

                ne.type,
                ne.reference_id,
                ne.message,
                ne.created_at,

                u.user_id AS sender_id,
                u.display_name AS sender_name,
                u.profile_image,
                u.gender

            FROM notifications n
            JOIN notification_events ne 
                ON ne.notification_event_id = n.notification_event_id
            JOIN users u 
                ON u.user_id = ne.sender_user_id

            WHERE n.user_id = ?
            ORDER BY ne.created_at DESC
            LIMIT ? OFFSET ?
        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("iii", $me, $limit, $offset);
            $stmt->execute();

            $result = $stmt->get_result();
            $data = [];

            while ($row = $result->fetch_assoc()) {
                $row["read"] = (bool) $row["is_read"];
                $row["time"] = $row["created_at"];
                unset($row["is_read"]);

                $data[] = $row;
            }

            Response::json([
                "status" => true,
                "page" => $page,
                "has_more" => $page < $total_pages,
                "total_pages" => $total_pages,
                "total" => $total,
                "data" => $data
            ]);
        } catch (\Throwable $e) {
            Response::json([
                "status" => false,
                "message" => "Failed to get notifications",
                "detail" => $e->getMessage()
            ], 500);
        }
    }

    public static function markAllAsRead()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = $user['user_id'];

        $sql = "UPDATE notifications SET is_read = 1 WHERE user_id = ?";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $me);

        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "All notifications are marked as read"
        ]);
    }

    public static function updateStatus()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = $user["user_id"];

        // $notification_id = (int) $_GET["notification_id"];
        $notification_id = (int) Request::input("id");

        if (!$notification_id) {
            Response::json([
                "status" => false,
                "message" => "Invalid notification id"
            ], 404);
        }
        try {
            $sql = "UPDATE notifications SET is_read = 1 WHERE notification_id = ? AND user_id = ?";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ii", $notification_id, $me);

            $stmt->execute();

            Response::json([
                "status" => true,
                "message" => "Status updated successful"
            ]);
        } catch (\Throwable $e) {
            Response::json([
                "status" => false,
                "message" => "Failed to update notification status",
                "detail" => $e->getMessage()
            ], 500);
        }
    }

    public static function getNotificationCount()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $me = (int) $user["user_id"];

        try {
            $sql = "
            SELECT 
                COUNT(*) AS total,
                SUM(is_read = 0) AS unread
            FROM notifications
            WHERE user_id = ?
        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $me);
            $stmt->execute();

            $result = $stmt->get_result()->fetch_assoc();

            Response::json([
                "status" => true,
                "data" => [
                    "total" => (int) $result["total"],
                    "unread" => (int) $result["unread"]
                ]
            ]);
        } catch (\Throwable $e) {
            Response::json([
                "status" => false,
                "message" => "Failed to get notification count",
                "detail" => $e->getMessage()
            ], 500);
        }
    }

    private static function getPagination()
    {
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $limit = 20;
        $offset = ($page - 1) * $limit;

        return [$page, $limit, $offset];
    }


}