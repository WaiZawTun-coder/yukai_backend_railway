<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Response;
use App\Core\Request;
use App\Service\ImageService;
use App\Service\PasswordService;
use App\Service\EmailService;

class UserController
{
    //return the user data
    public static function getUser()
    {
        $conn = Database::connect();
        $username = trim($_GET["username"] ?? "");

        $user_id = (int) trim($_GET["user_id"] ?? "");

        $authUser = Auth::getUser();
        $userId = (int) $authUser["user_id"];

        if ($username === "" && !$user_id) {
            Response::json([
                "status" => false,
                "message" => "Invalid Username and User ID"
            ], 400);
            return;
        }

        $userSql = "
        SELECT 
            u.user_id,
            u.username,
            u.display_name,
            u.gender,
            u.email,
            u.phone_number,
            u.profile_image,
            u.cover_image,
            u.bio,
            u.birthday,
            u.location,
            u.is_active,
            u.last_seen,
            u.default_audience,

            -- followers
            (
                SELECT COUNT(*) 
                FROM follows f 
                WHERE f.following_user_id = u.user_id
                  AND f.status = 1
            ) AS follower_count,

            -- following
            (
                SELECT COUNT(*) 
                FROM follows f 
                WHERE f.follower_user_id = u.user_id
                  AND f.status = 1
            ) AS following_count,

            -- friends
            (
                SELECT COUNT(*) 
                FROM friends fr
                WHERE (fr.user_1_id = u.user_id
                   OR fr.user_2_id = u.user_id) AND fr.status = 'accepted'
            ) AS friends_count,

            -- friend status (NULL if own profile)
            CASE
                WHEN u.user_id = ? THEN NULL
                ELSE (
                    SELECT fr.status
                    FROM friends fr
                    WHERE 
                        (fr.user_1_id = ? AND fr.user_2_id = u.user_id)
                     OR (fr.user_1_id = u.user_id AND fr.user_2_id = ?)
                    LIMIT 1
                )
            END AS friend_status,

            -- is following (FIXED)
            CASE
                WHEN u.user_id = ? THEN NULL
                ELSE (
                    SELECT COUNT(*) 
                    FROM follows f 
                    WHERE 
                        f.follower_user_id = ?
                        AND f.following_user_id = u.user_id
                        AND f.status = 1
                )
            END AS is_following,

            -- who sent request (NULL if own profile)
            CASE
                WHEN u.user_id = ? THEN NULL
                ELSE (
                    SELECT 
                        CASE
                            WHEN fr.user_1_id = ? THEN 'sent'
                            WHEN fr.user_2_id = ? THEN 'received'
                        END
                    FROM friends fr
                    WHERE 
                        (fr.user_1_id = ? AND fr.user_2_id = u.user_id)
                     OR (fr.user_1_id = u.user_id AND fr.user_2_id = ?)
                    LIMIT 1
                )
            END AS request_direction

        FROM users u
        WHERE u.username = ? or u.user_id = ? AND u.is_active = 1
        LIMIT 1
    ";

        $stmt = $conn->prepare($userSql);

        $stmt->bind_param(
            "iiiiiiiiiisi",

            // friend_status (3)
            $userId,
            $userId,
            $userId,

            // is_following (2)
            $userId,
            $userId,

            // request_direction (5)
            $userId,
            $userId,
            $userId,
            $userId,
            $userId,

            // username
            $username,
            $user_id
        );

        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();

        // ✅ Cast is_following into boolean
        if ($user["is_following"] !== null) {
            $user["is_following"] = ((int) $user["is_following"]) > 0;
        }

        Response::json([
            "status" => true,
            "message" => "User fetched successfully",
            "data" => $user
        ]);
    }


    // user edit
    public static function editUser()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        $display_name = trim(Request::input("display_name") ?? "");
        $email = trim(Request::input("email") ?? "");
        $password = trim(Request::input('password') ?? "");
        $bio = trim(Request::input("bio") ?? "");
        // $profile_image = trim(Request::input("profile_image") ?? "");
        $profile_image = Request::file("profile_image");
        $cover_image = Request::file("cover_image");
        $phone_number = trim(Request::input("phone_number") ?? "");

        // Check user exists
        $sql = "SELECT * FROM users WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();
        $updates = []; // Initialize as empty array
        $params = [];  // Initialize as empty array
        $types = "";

        // =====================================
        // NORMAL PROFILE UPDATES
        // =====================================

        if (!empty($display_name)) {
            $updates[] = "display_name = ?";
            $params[] = $display_name;
            $types .= "s";
        }
        if (!empty($email)) {
            EmailService::validate($email);
            if ($email !== $user['email']) {
                // Check if new email already exists for another admin
                $checkEmailSql = "SELECT user_id FROM users WHERE email = ? AND user_id != ?";
                $checkStmt = $conn->prepare($checkEmailSql);
                $checkStmt->bind_param("si", $email, $user_id);
                $checkStmt->execute();
                $emailResult = $checkStmt->get_result();

                if ($emailResult->num_rows > 0) {
                    Response::json([
                        "status" => false,
                        "message" => "Email already exists"
                    ]);

                }
                $updates[] = "email = ?";
                $params[] = $email;
                $types .= "s";
            }
        }
        if (!empty($password)) {
            PasswordService::isStrong($password);
            $hashpwd = password_hash($password, PASSWORD_DEFAULT);
            $updates[] = "password = ?";
            $params[] = $hashpwd;
            $types .= "s";
        }
        if (!empty($bio)) {
            $updates[] = "bio = ?";
            $params[] = $bio;
            $types .= "s";
        }
        if (!empty($profile_image)) {
            $profileImageUResult = ImageService::uploadImage($profile_image);
            $profileImageUrl = $profileImageUResult["secure_url"] ?? "";
            if ($profileImageUrl == "") {
                Response::json([
                    "status" => false,
                    "message" => "Failed to upload profile image"
                ], 500);
                return;
            }
            $updates[] = "profile_image = ?";
            $params[] = $profileImageUrl;
            $types .= "s";
        }
        if (!empty($cover_image)) {
            $coverImageResult = ImageService::uploadImage($cover_image);
            $coverImageUrl = $coverImageResult["secure_url"] ?? "";
            if ($coverImageUrl == "") {
                Response::json([
                    "status" => false,
                    "message" => "Failed to upload cover image"
                ], 500);
                return;
            }
            $updates[] = "cover_image = ?";
            $params[] = $coverImageUrl;
            $types .= "s";
        }
        if (!empty($phone_number)) {
            $updates[] = "phone_number = ?";
            $params[] = $phone_number;
            $types .= "s";
        }

        // Nothing to update
        if (empty($updates)) {
            Response::json([
                "status" => false,
                "message" => "No fields to update"
            ], 400);
            return;
        }

        $params[] = $user_id;
        $types .= "i";

        $sql = "UPDATE users SET " . implode(" ,", $updates) . " WHERE user_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$params);

        if ($stmt->execute()) {
            if ($stmt->affected_rows > 0) {
                Response::json([
                    "status" => true,
                    "message" => "User updated successfully"
                ], 200);
            } else {
                Response::json([
                    "status" => false,
                    "message" => "No changes were made"
                ], 200);
            }
        } else {
            // THIS WAS MISSING! Handle execute() failure
            Response::json([
                "status" => false,
                "message" => "Database error: " . $stmt->error
            ], 500);
        }

    }
    //request Password OTP
    public static function requestPasswordOTP()
    {
        $user = Auth::getUser();
        $user_id = $user["user_id"];
        $conn = Database::connect();

        // Check user exists
        $sql = "SELECT * FROM users WHERE user_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
        }

        $user = $result->fetch_assoc();

        // Generate OTP
        $otp = AuthController::generateOTP($user_id);
        if (!$otp) {
            Response::json([
                "status" => false,
                "message" => "Failed to generate OTP"
            ], 500);
        }

        // Send email
        $sent = AuthController::sendEmail($user['email'], $otp);
        if ($sent) {
            Response::json([
                "status" => true,
                "message" => "OTP sent to your email"
            ], 200);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to send OTP"
            ], 500);
        }
    }


    public static function changepassword()
    {

        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = $user["user_id"];
        $current_password = trim(Request::input("current_password") ?? "");
        $new_password = trim(Request::input("new_password") ?? "");
        $otpcode = trim(Request::input("otpcode") ?? "");


        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
            return;
        }

        if ((empty($current_password) && empty($otpcode)) || empty($new_password)) {
            Response::json([
                "status" => false,
                "message" => "Current password or OTP and new password are required"
            ], 400);
            return;
        }

        // Check user exists
        $stmt = $conn->prepare("SELECT password, email FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();

        // Verify current password
        if ($current_password) {
            if (!password_verify($current_password, $user['password'])) {
                Response::json([
                    "status" => false,
                    "message" => "Current password is incorrect"
                ], 400);
                return;
            }
        }
        // Verify OTP
        else if ($otpcode) {
            if (!AuthController::verifyOTP($user_id, $otpcode)) {
                Response::json([
                    "status" => false,
                    "message" => "OTP verification failed"
                ], 401);
                return;
            }
        }

        // 3. Hash new password
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

        // 4. Update password
        $update = $conn->prepare("UPDATE users SET password = ? WHERE user_id = ?");
        $update->bind_param("si", $hashed_password, $user_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "Password changed successfully"
            ], 200);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to update password"
            ], 500);
        }
    }

    //deactivate user
    public static function deactivateUser()
    {
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $deactivate = (int) (Request::input("deactivate") ?? 0);
        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
            return;
        }
        // Check user exists
        $stmt = $conn->prepare("SELECT password FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();
        //update deactivate
        $update = $conn->prepare("UPDATE users SET deactivate = ?  WHERE user_id = ?");
        $update->bind_param("ii", $deactivate, $user_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "User account is deactivated now"
            ], 200);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to deactivate userr account"
            ], 500);
        }
    }
    // In UserController.php or AuthController.php
    public static function generateOTPApi()
    {
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);

        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
            return;
        }

        // Check user exists
        $stmt = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();

        // Generate OTP using your existing function
        $otp = AuthController::generateOTP($user_id);

        if ($otp === false) {
            Response::json([
                "status" => false,
                "message" => "Failed to generate OTP"
            ], 500);
            return;
        }

        // In production: Send OTP via email/SMS here
        // For now, just return success
        Response::json([
            "status" => true,
            "message" => "OTP sent successfully to " . $user['email']
        ], 200);
    }

    //deleted account
    public static function deletedAccount()
    {
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $deleted_account = (int) (Request::input("deleted_account") ?? 0);
        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
            return;
        }
        // Check user exists
        $stmt = $conn->prepare("SELECT password FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();
        //update deactivate
        $update = $conn->prepare("UPDATE users SET deleted_account = ?, deactivate = 1, is_active = 0  WHERE user_id = ?");
        $update->bind_param("ii", $deleted_account, $user_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "User account is deleted now"
            ], 200);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to deleted user account"
            ], 500);
        }
    }


    /* =============== Deactivate Account ======================== */
    public static function deactivateAccount()
    {
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0); // logged in user
        $deactivate = (int) (Request::input("deactivate") ?? 0);
        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
            return;
        }
        // Check user exists
        $stmt = $conn->prepare("SELECT password FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();
        //update deactivate
        $update = $conn->prepare("UPDATE users SET deactivate = ?, is_active = 0  WHERE user_id = ?");
        $update->bind_param("ii", $deactivate, $user_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "Deactivate Account"
            ], 200);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to deactivate your account"
            ], 500);
        }
    }

    public static function getAccountHealth()
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

        $conn = Database::connect();
        $sql = "SELECT status FROM users WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        $row = $result->fetch_assoc();

        Response::json([
            "status" => true,
            "account_health" => $row["status"]
        ]);
        return;
    }

}
