<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Response;
use App\Core\Request;
class PrivacyController
{
    public static function getDefault()
    {
        // $userId = $_SESSION['user_id'] ?? 0;
        $user = Auth::getUser();
        $userId = $user["user_id"];

        if (!$userId) {
            Response::json([
                "status" => false,
                "message" => "Not Authorized"
            ], 400);
            return;
        }

        $conn = Database::connect();
        // Select the yukai database
        $conn->select_db("yukai");

        $sql = "SELECT default_audience FROM users WHERE user_id = ?";
        $stmt = $conn->prepare($sql);

        if (!$stmt) {
            Response::json([
                "status" => false,
                "message" => "Unknown Error"
            ], 500);
            return;
        }

        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            $privacy = $row['default_audience'];
        } else {
            $privacy = 'public'; // Default value
        }

        Response::json([
            "status" => true,
            "default_privacy" => $privacy
        ]);
        return;
    }

    // Update user's default privacy setting
    public static function updateDefault()
    {
        $user = Auth::getUser();
        $userId = $user["user_id"];

        if (!$userId) {
            Response::json([
                "status" => false,
                "message" => "Not authenticated"
            ], 401);
        }

        // Get privacy from request
        // $data = json_decode(file_get_contents('php://input'), true);
        $privacy = Request::input("privacy") ?? 'public';

        // Validate
        $allowed = ['public', 'friends', 'private'];
        if (!in_array($privacy, $allowed)) {
            Response::json([
                "status" => false,
                "message" => "Invalid privacy value"
            ], 400);
        }

        $conn = Database::connect();

        // Insert or update
        // $sql = "INSERT INTO users (user_id, default_privacy) 
        //         VALUES (?, ?)
        //         ON DUPLICATE KEY UPDATE default_privacy = ?";
        $sql = "UPDATE users SET default_audience = ? WHERE user_id = ?";

        $stmt = $conn->prepare($sql);

        if (!$stmt) {
            error_log("SQL Error in updateDefault: " . $conn->error);
            Response::json([
                "status" => false,
                "message" => "Database error"
            ], 500);
        }

        $stmt->bind_param("si", $privacy, $userId);
        $success = $stmt->execute();

        if ($success) {
            Response::json([
                "status" => true,
                "message" => "Default privacy updated",
                "default_privacy" => $privacy
            ]);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to update"
            ], 500);
        }
    }

    public static function get2fa()
    {
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        if (!$user_id) {
            Response::json(["status" => false, "message" => "Not Authorized"], 400);
            return;
        }

        $conn = Database::connect();

        $sql = "SELECT is_2fa FROM users where user_id = ?";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);

        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            $is_2fa = (int) $row['is_2fa'] == 1;
        } else {
            $is_2fa = false;
        }

        Response::json([
            "statua" => true,
            "two_factor_enabled" => $is_2fa
        ]);
        return;
    }

    public static function update2fa()
    {
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        if (!$user_id) {
            Response::json([
                "status" => false,
                "message" => "Not Authorized"
            ], 400);
            return;
        }

        $is_2fa = Request::input("enabled") ? 1 : 0;

        $conn = Database::connect();
        $sql = "UPDATE users SET is_2fa = ? WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $is_2fa, $user_id);

        $success = $stmt->execute();

        if ($success) {
            Response::json([
                "status" => true,
                "message" => "Successfully updated 2 factor authentication"
            ]);
            return;
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to update 2 factor authentication"
            ], 500);
            return;
        }
    }
}
