<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\JWT;
use App\Core\Request;
use App\Core\Response;
use App\Core\Database;
use App\Core\Generator;
use App\Service\TokenService;
use App\Service\PasswordService;
use App\Service\ImageService;
use App\Service\EmailService;
use DateTime;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../../phpmailer/Exception.php';
require_once __DIR__ . '/../../phpmailer/PHPMailer.php';
require_once __DIR__ . '/../../phpmailer/SMTP.php';

class AuthController
{
    const MAX_ATTEMPTS = 5;
    const LOCK_MINUTES = 15;

    public static function index()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        if ($user_id == null)
            Response::json([
                "status" => false,
                "message" => "Invalid user id"
            ], 404);

        $userSql = "
            SELECT user_id, username, display_name, gender, email,
                   phone_number, profile_image, cover_image, birthday,
                   location, is_active, last_seen, default_audience, completed_step
            FROM users
            WHERE user_id = ?
        ";

        $stmt = $conn->prepare($userSql);
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

        Response::json([
            "status" => true,
            "data" => $user
        ]);
    }

    public static function login()
    {
        $conn = Database::connect();
        $input = Request::json();

        $username = trim($input['username'] ?? '');
        $password = trim($input['password'] ?? '');
        $device_id = trim(Request::input("device_id") ?? "");

        if ($username === '' || $password === '') {
            Response::json(["status" => false, "message" => "Username and Password required"], 400);
            return;
        }
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? OR username = ? LIMIT 1");
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json(["status" => false, "message" => "Account not found"], 404);
            return;
        }

        $user = $result->fetch_assoc();

        if ($user["locked_until"] && strtotime($user["locked_until"]) > time()) {
            Response::json([
                "status" => false,
                "message" => "Account locked. Try again later."
            ]);
            return;
        }

        if ((int) $user['is_active'] === 0) {
            Response::json(["status" => false, "message" => "Account is not active"], 403);
            return;
        }

        if (in_array(trim($user['status']), ['suspend_user', 'ban_user'])) {
            Response::json([
                "status" => false,
                "message" => "The user account is " . str_replace('_', ' ', $user['status'])
            ], 403);
            return;
        }

        if (!PasswordService::verify($password, $user['password'])) {
            self::handleFailedAttempt($user);
            Response::json(["status" => false, "message" => "Incorrect password"], 401);
            return;
        }

        // Reactivate account if deactivated
        if ((int) $user['deactivate'] === 1) {
            $stmt = $conn->prepare("UPDATE users SET deactivate = 0 WHERE user_id = ?");
            $stmt->bind_param("i", $user['user_id']);
            $stmt->execute();
            $user['deactivate'] = 0;
        }

        /**
         * =====================
         * 🔐 TWO FACTOR AUTH
         * =====================
         */
        if ((int) $user['is_2fa'] === 1) {

            $otpCode = self::generateOTP($user['user_id']);
            if (!$otpCode) {
                Response::json(["status" => false, "message" => "Failed to generate OTP"]);
                return;
            }

            self::sendEmail($user['email'], $otpCode);

            $accessToken = TokenService::generateAccessToken([
                "user_id" => $user['user_id'],
                "username" => $user['username'],
                "two_factor_verified" => false
            ], 300);


            self::resetAttempts($user["user_id"]);
            Response::json([
                "status" => true,
                "two_factor_required" => true,
                "message" => "OTP sent to your email",
                "data" => [
                    "user_id" => $user['user_id'],
                    "access_token" => $accessToken
                ]
            ]);
            return;
        }

        /**
         * =====================
         * 🔑 NORMAL LOGIN
         * =====================
         */
        $accessToken = TokenService::generateAccessToken([
            "user_id" => $user['user_id'],
            "username" => $user['username'],
            "scope" => "registration",
            "two_factor_verified" => true
        ]);

        $refreshPayload = TokenService::generateRefreshToken();
        $refreshToken = $refreshPayload["token"];
        $refreshHash = $refreshPayload["hash"];

        $expireAt = date("Y-m-d H:i:s", time() + 60 * 60 * 24 * 7);

        // Save hashed refresh token to refresh_tokens table
        $stmt = $conn->prepare("
    INSERT INTO refresh_tokens (user_id, device_id, token_hash, issued_at, expires_at)
    VALUES (?, ?, ?, NOW(), ?)
");
        $stmt->bind_param("isss", $user['user_id'], $device_id, $refreshHash, $expireAt);
        $stmt->execute();

        // Set cookie
        $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
        setcookie("refresh_token", $refreshToken, [
            "expires" => time() + 60 * 60 * 24 * 7,
            "path" => "/",
            "secure" => $isSecure,
            "httponly" => true,
            "samesite" => $isSecure ? "None" : "Lax"
        ]);

        // Incomplete registration
        if ((int) $user['completed_step'] < 2) {
            Response::json([
                "status" => true,
                "incomplete" => true,
                "message" => "Registration not completed",
                "data" => [
                    "user_id" => $user['user_id'],
                    "username" => $user['username'],
                    "email" => $user['email'],
                    "completed_step" => $user['completed_step'],
                    "access_token" => $accessToken
                ]
            ]);
            return;
        }

        if ($device_id) {

            // Validate device belongs to user
            $stmt = $conn->prepare("
                SELECT device_id 
                FROM devices 
                WHERE device_id = ? AND user_id = ?
                LIMIT 1
            ");
            $stmt->bind_param("si", $device_id, $user['user_id']);
            $stmt->execute();

            if ($stmt->get_result()->num_rows > 0) {

                // Insert login history
                $stmt = $conn->prepare("
                    INSERT INTO login_histories (user_id, device_id, logged_in_time)
                    VALUES (?, ?, NOW())
                ");
                $stmt->bind_param("is", $user['user_id'], $device_id);
                $stmt->execute();

                // Update last_seen_at
                $stmt = $conn->prepare("
                    UPDATE devices 
                    SET last_seen_at = NOW(), is_active = 1
                    WHERE device_id = ?
                ");
                $stmt->bind_param("s", $device_id);
                $stmt->execute();
            }
        }

        $stmt = $conn->prepare("UPDATE users SET last_seen = NOW() WHERE user_id = ?");
        $stmt->bind_param("i", $user["user_id"]);
        $stmt->execute();

        self::resetAttempts($user["user_id"]);
        Response::json([
            "status" => true,
            "message" => "Login successful",
            "data" => [
                "user_id" => $user["user_id"],
                "username" => $user["username"],
                "email" => $user["email"],
                "display_name" => $user["display_name"],
                "gender" => $user["gender"],
                "phone_number" => $user["phone_number"],
                "profile_image" => $user["profile_image"],
                "cover_image" => $user["cover_image"],
                "birthday" => $user["birthday"],
                "location" => $user["location"],
                "is_active" => $user["is_active"],
                "last_seen" => $user["last_seen"],
                "access_token" => $accessToken,
                "completed_step" => $user["completed_step"]
            ]
        ]);
    }

    private static function handleFailedAttempt($user)
    {
        $conn = Database::connect();

        $failed = $user["failed_attempts"] + 1;
        $lockedUntil = null;

        if ($failed >= self::MAX_ATTEMPTS) {
            $lockedUntil = date(
                "Y-m-d H:i:s",
                time() + (self::LOCK_MINUTES * 60)
            );
        }

        $stmt = $conn->prepare("
            UPDATE users 
            SET failed_attempts = ?,
                locked_until = ?,
                last_failed_at = NOW()
            WHERE user_id = ?
        ");
        $stmt->bind_param("isi", $failed, $lockedUntil, $user["user_id"]);

        $stmt->execute();

        // Progressive delay
        sleep(min($failed * 2, 10));
    }

    private static function resetAttempts($userId)
    {
        $conn = Database::connect();

        $stmt = $conn->prepare("
            UPDATE users 
            SET failed_attempts = 0,
                locked_until = NULL
            WHERE user_id = ?
        ");

        $stmt->bind_param("i", $userId);
        $stmt->execute();
    }

    public static function logout()
    {
        $user = Auth::getUser();
        $user_id = $user['user_id'];

        $device_id = Request::input("device_id") ?? "";
        if (!$device_id) {
            Response::json([
                "status" => false,
                "message" => "Invalid Device Id"
            ], 400);
            return;
        }

        $conn = Database::connect();
        $sql = "UPDATE refresh_tokens SET revoked = 1 WHERE device_id = ? AND user_id = ?";
        $stmt = $conn->prepare($sql);

        $stmt->bind_param("si", $device_id, $user_id);
        $stmt->execute();

        Response::json([
            'status' => true,
            "message" => "Logged out successful"
        ]);
    }

    // need to add protect in step 2
    public static function register($username = "")
    {
        $conn = Database::connect();
        $input = Request::json();
        $step = 1;

        if ($username !== "") {
            $stmt = $conn->prepare("SELECT completed_step FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $res = $stmt->get_result();

            if ($res->num_rows === 0) {
                Response::json(["status" => false, "message" => "User not found"], 404);
            }

            $step = ((int) $res->fetch_assoc()['completed_step']) + 1;
        }

        switch ($step) {
            case 1:
                $username = trim($input["username"] ?? "");
                $password = trim($input["password"] ?? "");
                $email = trim($input["email"] ?? "");

                if ($username === "" || $password === "" || $email === "") {
                    Response::json(["status" => false, "message" => "All fields required"], 400);
                }
                EmailService::validate($email);
                $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();

                if ($stmt->get_result()->num_rows > 0) {
                    Response::json(["status" => false, "message" => "Email already registered"], 409);
                }


                $generatedUsername = Generator::generateUsername($username);
                //test strong password
                PasswordService::isStrong($password);
                $hash = PasswordService::hash($password);
                $stmt = $conn->prepare("INSERT INTO users (username, display_name, password, email, completed_step) VALUES (?, ?, ?, ?, 1)");
                $stmt->bind_param("ssss", $generatedUsername, $username, $hash, $email);
                $stmt->execute();

                $userId = $conn->insert_id;

                $accessToken = TokenService::generateAccessToken(
                    [
                        "user_id" => $userId,
                        "username" => $generatedUsername,
                        "scope" => "registration"
                    ],
                    600
                );

                Response::json([
                    "status" => true,
                    "step" => 2,
                    "data" => [
                        "userId" => $userId,
                        "email" => $email,
                        "generated_username" => $generatedUsername,
                        "access_token" => $accessToken
                    ]
                ]);
                break;
            case 2:
                $userId = (int) trim(Request::input("userId") ?? 0);
                $bodyUsername = trim(Request::input("username") ?? "");
                $dateOfBirth = trim(Request::input("dateOfBirth") ?? "");
                $gender = trim(Request::input("gender") ?? "");
                $phoneNumber = trim(Request::input("phoneNumber") ?? "");
                $email = trim(Request::input("email") ?? "");
                $profileImage = Request::file("profileImage");

                //
                $headers = getallheaders();
                $authHeader = $headers["Authorization"] ?? $headers["authorization"] ?? null;
                if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
                    Response::json([
                        "status" => false,
                        "message" => "Unauthorized"
                    ], 401);
                }
                $token = $matches[1];
                try {
                    $payload = JWT::decode($token, $_ENV["JWT_SECRET"]);
                } catch (\Exception $e) {
                    Response::json([
                        "status" => false,
                        "message" => "Invalid or expired token"
                    ], 401);
                }

                if (($payload["scope"] ?? null) !== "registration") {
                    Response::json([
                        "status" => false,
                        "message" => "Invalid token scope"
                    ], 403);
                }

                if ($payload["user_id"] != $userId) {
                    Response::json([
                        "status" => false,
                        "message" => "Token mismatch"
                    ], 401);
                }

                if ($profileImage != null && $profileImage["error"] !== UPLOAD_ERR_OK) {
                    Response::json([
                        "status" => false,
                        "message" => "Upload Failed"
                    ], 400);
                }

                // Required fields
                if ($bodyUsername === "") {
                    Response::json(["status" => false, "message" => "Username Required"], 400);
                }

                if ($dateOfBirth === "") {
                    Response::json(["status" => false, "message" => "Date of birth Required"], 400);
                }

                if ($gender === "") {
                    Response::json(["status" => false, "message" => "Gender Required"], 400);
                }

                // Validate date format
                $birthday = DateTime::createFromFormat("Y-m-d", $dateOfBirth);
                $errors = DateTime::getLastErrors();

                if (!$birthday) {
                    Response::json(["status" => false, "message" => "Invalid date format"], 400);
                }

                // Prevent future dates
                $today = new DateTime("today");
                if ($birthday > $today) {
                    Response::json(["status" => false, "message" => "Date of birth cannot be in the future"], 400);
                }

                // Age check (13+)
                $age = $birthday->diff($today)->y;
                if ($age < 13) {
                    Response::json(["status" => false, "message" => "You must be at least 13 years old"], 400);
                }

                // Username availability (only if changed)
                if ($username !== $bodyUsername) {
                    $checkSql = "SELECT user_id FROM users WHERE username = ? LIMIT 1";
                    $checkStmt = $conn->prepare($checkSql);
                    $checkStmt->bind_param("s", $bodyUsername);
                    $checkStmt->execute();
                    $checkResult = $checkStmt->get_result();

                    if ($checkResult->num_rows > 0) {
                        Response::json([
                            "status" => false,
                            "message" => "$bodyUsername is not available"
                        ], 409);
                    }
                }

                if ($profileImage != null) {
                    $uploadImageResult = ImageService::uploadImage($profileImage);
                }
                $imageUrl = $uploadImageResult["secure_url"] ?? "";

                // Update user
                $updateSql = "
                            UPDATE users 
                            SET 
                                username = ?, 
                                birthday = ?, 
                                gender = ?, 
                                phone_number = ?, 
                                profile_image = ?,
                                completed_step = 2
                            WHERE username = ? AND email = ?
                        ";

                $birthdaySql = $birthday->format("Y-m-d");

                $updateStmt = $conn->prepare($updateSql);
                $updateStmt->bind_param(
                    "sssssss",
                    $bodyUsername,
                    $birthdaySql,
                    $gender,
                    $phoneNumber,
                    $imageUrl,
                    $username,
                    $email
                );

                $updateStmt->execute();

                if ($updateStmt->affected_rows == 0) {
                    Response::json([
                        "status" => false,
                        "message" => "Registration failed - step 2"
                    ], 500);
                }
                

                $isSecure =
                    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                    || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

                setcookie("refresh_token", "", [
                    "expires" => time() - 3600,
                    "path" => "/",
                    "secure" => $isSecure,
                    "httponly" => true,
                    "samesite" => $isSecure ? "None" : "Lax",
                ]);

                Response::json([
                    "status" => true,
                    "message" => "Step 2 completed successfully"
                ]);
                break;
            default:
                Response::json([
                    "status" => false,
                    "message" => "Invalid Registration Step"
                ]);
                break;
        }
    }

    public static function refresh()
    {
        $conn = Database::connect();

        $isSecure =
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

        $refreshToken = $_COOKIE["refresh_token"] ?? null;
        $device_id = Request::input("device_id") ?? "";
        $scope = Request::input("scope") ?? "";

        if (!$refreshToken) {
            Response::json([
                "status" => false,
                "message" => "Refresh token missing"
            ], 401);
            return;
        }

        $refreshHash = hash("sha256", $refreshToken);

        // Lookup in refresh_tokens table
        $stmt = $conn->prepare("
        SELECT rt.id, rt.user_id, rt.expires_at, u.username, u.is_active
        FROM refresh_tokens rt
        JOIN users u ON u.user_id = rt.user_id
        WHERE rt.token_hash = ? AND rt.revoked = 0
        LIMIT 1
    ");
        $stmt->bind_param("s", $refreshHash);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            // Invalid token
            setcookie("refresh_token", "", [
                "expires" => time() - 3600,
                "path" => "/",
                "secure" => $isSecure,
                "httponly" => true,
                "samesite" => $isSecure ? "None" : "Lax",
            ]);

            Response::json([
                "status" => false,
                "message" => "Invalid refresh token"
            ], 401);
            return;
        }

        
        $tokenData = $result->fetch_assoc();
        $is_active = $tokenData["is_active"] ?? 0;
        if((int) $is_active == 0){
            // Invalid token
            setcookie("refresh_token", "", [
                "expires" => time() - 3600,
                "path" => "/",
                "secure" => $isSecure,
                "httponly" => true,
                "samesite" => $isSecure ? "None" : "Lax",
            ]);

            Response::json([
                "status" => false,
                "message" => "Account is banned"
            ], 401);
            return;
        }

        // Check expiry
        if (strtotime($tokenData["expires_at"]) < time()) {
            // Revoke expired token
            $stmt = $conn->prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?");
            $stmt->bind_param("i", $tokenData["id"]);
            $stmt->execute();

            setcookie("refresh_token", "", [
                "expires" => time() - 3600,
                "path" => "/",
                "secure" => $isSecure,
                "httponly" => true,
                "samesite" => $isSecure ? "None" : "Lax"
            ]);

            Response::json([
                "status" => false,
                "message" => "Refresh token expired"
            ], 401);
            return;
        }

        // Rotate refresh token (generate new one)
        $refreshPayload = TokenService::generateRefreshToken();
        $newRefreshToken = $refreshPayload["token"];
        $newRefreshHash = $refreshPayload["hash"];
        $newExpire = date("Y-m-d H:i:s", time() + 604800); // 7 days

        // Insert new refresh token
        $stmt = $conn->prepare("
        INSERT INTO refresh_tokens (user_id, device_id, token_hash, issued_at, expires_at)
        VALUES (?, ?, ?,NOW(), ?)
    ");
        $stmt->bind_param("isss", $tokenData["user_id"], $device_id, $newRefreshHash, $newExpire);
        $stmt->execute();

        // Revoke old token
        $stmt = $conn->prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?");
        $stmt->bind_param("i", $tokenData["id"]);
        $stmt->execute();

        // Set cookie for client
        setcookie("refresh_token", $newRefreshToken, [
            "expires" => time() + 604800,
            "path" => "/",
            "secure" => $isSecure,
            "httponly" => true,
            "samesite" => $isSecure ? "None" : "Lax"
            
        ]);

        // Generate new access token
        $token_data = empty($scope) ? [
            "user_id" => $tokenData["user_id"],
            "username" => $tokenData["username"]
        ] : [
            "user_id" => $tokenData["user_id"],
            "username" => $tokenData["username"],
            "scope" => $scope
        ];
        $accessToken = TokenService::generateAccessToken($token_data);

        $stmt = $conn->prepare("UPDATE users SET last_seen = NOW() WHERE user_id = ?");
        $stmt->bind_param("i", $tokenData["user_id"]);
        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Token refreshed",
            "data" => [
                "access_token" => $accessToken
            ]
        ]);
    }

    private static function internalRefresh()
    {
        $conn = Database::connect();

        $isSecure =
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

        $refreshToken = $_COOKIE["refresh_token"] ?? null;
        $device_id = Request::input("device_id") ?? "";

        if (!$refreshToken) {
            Response::json([
                "status" => false,
                "message" => "Refresh token missing"
            ], 401);
            return;
        }

        $refreshHash = hash("sha256", $refreshToken);

        // Lookup in refresh_tokens table
        $stmt = $conn->prepare("
        SELECT rt.id, rt.user_id, rt.expires_at, u.username
        FROM refresh_tokens rt
        JOIN users u ON u.user_id = rt.user_id
        WHERE rt.token_hash = ? AND rt.revoked = 0
        LIMIT 1
    ");
        $stmt->bind_param("s", $refreshHash);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            // Invalid token
            setcookie("refresh_token", "", [
                "expires" => time() - 3600,
                "path" => "/",
                "secure" => $isSecure,
                "httponly" => true,
                "samesite" => $isSecure ? "None" : "Lax",
            ]);

            Response::json([
                "status" => false,
                "message" => "Invalid refresh token"
            ], 401);
            return;
        }

        $tokenData = $result->fetch_assoc();

        // Check expiry
        if (strtotime($tokenData["expires_at"]) < time()) {
            // Revoke expired token
            $stmt = $conn->prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?");
            $stmt->bind_param("i", $tokenData["id"]);
            $stmt->execute();

            setcookie("refresh_token", "", [
                "expires" => time() - 3600,
                "path" => "/",
                "secure" => $isSecure,
                "httponly" => true,
                "samesite" => $isSecure ? "None" : "Lax"
            ]);

            Response::json([
                "status" => false,
                "message" => "Refresh token expired"
            ], 401);
            return;
        }

        // Rotate refresh token (generate new one)
        $refreshPayload = TokenService::generateRefreshToken();
        $newRefreshToken = $refreshPayload["token"];
        $newRefreshHash = $refreshPayload["hash"];
        $newExpire = date("Y-m-d H:i:s", time() + 604800); // 7 days

        // Insert new refresh token
        $stmt = $conn->prepare("
        INSERT INTO refresh_tokens (user_id, device_id, token_hash, issued_at, expires_at)
        VALUES (?, ?, ?,NOW(), ?)
    ");
        $stmt->bind_param("isss", $tokenData["user_id"], $device_id, $newRefreshHash, $newExpire);
        $stmt->execute();

        // Revoke old token
        $stmt = $conn->prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?");
        $stmt->bind_param("i", $tokenData["id"]);
        $stmt->execute();

        // Set cookie for client
        setcookie("refresh_token", $newRefreshToken, [
            "expires" => time() + 604800,
            "path" => "/",
            "secure" => $isSecure,
            "httponly" => true,
            "samesite" => $isSecure ? "None" : "Lax"
            
        ]);

        // Generate new access token
        $token_data = [
            "user_id" => $tokenData["user_id"],
            "username" => $tokenData["username"]
        ];
        $accessToken = TokenService::generateAccessToken($token_data);

        $stmt = $conn->prepare("UPDATE users SET last_seen = NOW() WHERE user_id = ?");
        $stmt->bind_param("i", $tokenData["user_id"]);
        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Token refreshed",
            "data" => [
                "access_token" => $accessToken
            ]
        ]);
    }

    // generate OTP 
    public static function generateOTP($user_id)
    {
        $conn = Database::connect();

        if (!$user_id) {
            $user = Auth::getUser();
            $user_id = $user['user_id'];
        }

        $otpcode = '';
        for ($i = 0; $i < 8; $i++) {
            $otpcode .= random_int(0, 9);
        }
        $expiryMinutes = 5;

        $hashedOtp = password_hash($otpcode, PASSWORD_DEFAULT);

        // Clean up existing OTPs for this user
        $cleanupStmt = $conn->prepare("
                DELETE FROM otp 
                WHERE user_id = ?
            ");
        $cleanupStmt->bind_param("i", $user_id);
        $cleanupStmt->execute();

        // Insert new OTP record (NOT USED YET)
        $stmt = $conn->prepare("
                INSERT INTO otp (user_id, otp_code, expiration_time)
                VALUES (?, ?, NOW() + INTERVAL 5 MINUTE);
            ");
        $stmt->bind_param("is", $user_id, $hashedOtp);

        if (!$stmt->execute()) {
            return false;
        }

        return $otpcode;
    }


    // Verify OTP
    public static function verifyOTP()
    {
        $conn = Database::connect();

        $user = Auth::getUser();
        $userId = (int) ($user["user_id"] ?? 0);
        $otpCode = trim(Request::input("otp"));
        $deviceId = Request::input("device_id");

        if (!$userId || !$otpCode || !$deviceId) {
            Response::json(["error" => "Missing required fields."], 400);
        }

        // Fetch latest unused OTP
        $stmt = $conn->prepare("
        SELECT otp_id, otp_code, expiration_time, attempts
        FROM otp
        WHERE user_id = ?
          AND is_used = 0
        ORDER BY expiration_time DESC
        LIMIT 1
    ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $otpRecord = $result->fetch_assoc();

        if (!$otpRecord) {
            Response::json(["error" => "Invalid or expired OTP."], 400);
        }

        // 🚫 Rate limit check
        if ($otpRecord['attempts'] >= 5) {
            // update the otp as used to prevent further attempts
            $stmt = $conn->prepare(
                "UPDATE otp SET is_used = 1 WHERE user_id = ?;"
            );
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            
            Response::json([
                "error" => "Too many failed attempts. Please request a new OTP."
            ], 429);
        }

        // ⏰ Expiration check
        if (strtotime($otpRecord['expiration_time']) < time()) {
            Response::json(["error" => "OTP has expired."], 400);
        }

        // ❌ Wrong OTP
        if (!password_verify($otpCode, $otpRecord['otp_code'])) {

            // Increment attempts
            $updateAttempts = $conn->prepare("
            UPDATE otp 
            SET attempts = attempts + 1
            WHERE otp_id = ?
        ");
            $updateAttempts->bind_param("i", $otpRecord['otp_id']);
            $updateAttempts->execute();

            Response::json(["error" => "Invalid OTP."], 400);
        }

        // ✅ Correct OTP — begin transaction
        $conn->begin_transaction();

        try {

            // Mark OTP as used
            $markUsed = $conn->prepare("
            UPDATE otp 
            SET is_used = 1 
            WHERE otp_id = ?
        ");
            $markUsed->bind_param("i", $otpRecord['otp_id']);
            $markUsed->execute();

            // Fetch user info
            $userStmt = $conn->prepare("
            SELECT user_id, username, email
            FROM users
            WHERE user_id = ?
            LIMIT 1
        ");
            $userStmt->bind_param("i", $userId);
            $userStmt->execute();
            $userResult = $userStmt->get_result();
            $user = $userResult->fetch_assoc();

            if (!$user) {
                throw new Exception("User not found.");
            }

            // 🔒 Revoke old refresh tokens for this device
            $revoke = $conn->prepare("
            UPDATE refresh_tokens
            SET revoked = 1
            WHERE user_id = ? AND device_id = ?
        ");
            $revoke->bind_param("is", $userId, $deviceId);
            $revoke->execute();

            // 🔑 Generate tokens
            $accessToken = TokenService::generateAccessToken($user);

            $refreshToken = bin2hex(random_bytes(64));
            $refreshHash = hash("sha256", $refreshToken);

            $expiresAt = date("Y-m-d H:i:s", time() + (7 * 24 * 60 * 60));

            // Store refresh token
            $insert = $conn->prepare("
            INSERT INTO refresh_tokens
            (user_id, device_id, token_hash, expires_at, revoked)
            VALUES (?, ?, ?, ?, 0)
        ");
            $insert->bind_param("isss", $userId, $deviceId, $refreshHash, $expiresAt);
            $insert->execute();

            $conn->commit();

        } catch (Exception $e) {
            $conn->rollback();
            Response::json(["error" => "OTP verification failed."], 500);
        }

        // 🍪 Secure cookie settings
        // $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

        // setcookie(
        //     "refresh_token",
        //     $refreshToken,
        //     [
        //         "expires"  => time() + (7 * 24 * 60 * 60),
        //         "path"     => "/",
        //         "secure"   => $isSecure,
        //         "httponly" => true,
        //         "samesite" => "Strict"
        //     ]
        // );

        // Response::json([
        //     "message" => "OTP verified successfully.",
        //     "access_token" => $accessToken
        // ], 200);
        return true;
    }


    public static function sendEmail($email, $otpcode)
{
    if (empty($email)) {
        Response::json([
            "status" => false,
            "message" => "Email address is required"
        ], 400);
        return false;
    }

    $apiKey = $_ENV['BREVO_API_KEY'];
    $sender = $_ENV['BREVO_SENDER'];

    $data = [
        "sender" => [
            "name" => "Yukai Support",
            "email" => $sender
        ],
        "to" => [
            ["email" => $email]
        ],
        "subject" => "Your verification code",
        "htmlContent" => "
            Hello,<br><br>
            Your OTP code is:<br><br>
            <h2>$otpcode</h2>
            This OTP is valid for 5 minutes.<br><br>
            Do not share this code with anyone.<br><br>
            Yukai Support Team
        "
    ];

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, "https://api.brevo.com/v3/smtp/email");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "accept: application/json",
        "api-key: $apiKey",
        "content-type: application/json"
    ]);

    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        Response::json([
            "status" => false,
            "message" => "Failed to send email",
            "error" => $error
        ], 500);
        return false;
    }

    return true;
}

    //forget password function

    public static function forgetPassword()
    {
        $conn = Database::connect();
        $email = trim(Request::input("email") ?? "");

        if ($email === "") {
            Response::json([
                "status" => false,
                "message" => "Email is required"
            ], 400);
        }
        EmailService::validate($email);

        $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        if (!$user) {
            Response::json([
                "status" => false,
                "message" => "This email is not registered in our system."
            ], 404);
        }

        $otpcode = self::generateOTP($user['user_id']);

        if (!$otpcode) {
            Response::json([
                "status" => false,
                "message" => "Failed to generate OTP"
            ], 500);
        }

        self::sendEmail($email, $otpcode);

        Response::json([
            "status" => true,
            "message" => "OTP sent to your email"
        ]);
    }

    //reset password
    public static function resetPassword()
    {
        $conn = Database::connect();

        // $user_id = (int) (Request::input("user_id") ?? 0);
        $email = trim(Request::input("email") ?? "");
        $otpcode = trim(Request::input("otp") ?? "");
        $newPassword = Request::input("password") ?? "";

        if ($email === "" || $otpcode === "" || $newPassword === "") {
            Response::json([
                "status" => false,
                "message" => "All fields are required"
            ], 400);
        }

        $getUserId = "SELECT user_id FROM users where email=?";
        $getUserIdStmt = $conn->prepare($getUserId);
        $getUserIdStmt->bind_param("s", $email);
        $getUserIdStmt->execute();

        $getUserIdResult = $getUserIdStmt->get_result();
        $user_id = $getUserIdResult->fetch_assoc()["user_id"];
        PasswordService::isStrong($newPassword);

        if (!self::verifyOTPWithEmail($email, $otpcode)) {
            Response::json([
                "status" => false,
                "message" => "Invalid or expired OTP"
            ], 401);
        }

        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE user_id = ?");
        $stmt->bind_param("si", $hashedPassword, $user_id);
        $stmt->execute();


        Response::json([
            "status" => true,
            "message" => "Password reset successfully"
        ]);
    }

    private static function verifyOTPWithEmail($email, $otpCode){
        $conn = Database::connect();
        
        // get user_id
        $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();

        $result = $stmt->get_result();
        $user_id = $result->fetch_assoc()["user_id"] ?? null;

        if(!$user_id){
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 400);
            return false;
        }

        $stmt = $conn->prepare("
        SELECT otp_id, otp_code, expiration_time, attempts
        FROM otp
        WHERE user_id = ?
          AND is_used = 0
        ORDER BY expiration_time DESC
        LIMIT 1
    ");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $otpRecord = $result->fetch_assoc();

        if (!$otpRecord) {
            Response::json(["error" => "Invalid or expired OTP.", "email" => $email, "user_id" => $user_id], 400);
        }

        // 🚫 Rate limit check
        if ($otpRecord['attempts'] >= 5) {
            // update the otp as used to prevent further attempts
            $stmt = $conn->prepare(
                "UPDATE otp SET is_used = 1 WHERE user_id = ?;"
            );
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            
            Response::json([
                "error" => "Too many failed attempts. Please request a new OTP."
            ], 429);
        }

        // ⏰ Expiration check
        if (strtotime($otpRecord['expiration_time']) < time()) {
            Response::json(["error" => "OTP has expired."], 400);
        }

        // ❌ Wrong OTP
        if (!password_verify($otpCode, $otpRecord['otp_code'])) {

            // Increment attempts
            $updateAttempts = $conn->prepare("
            UPDATE otp 
            SET attempts = attempts + 1
            WHERE otp_id = ?
        ");
            $updateAttempts->bind_param("i", $otpRecord['otp_id']);
            $updateAttempts->execute();

            Response::json(["error" => "Invalid OTP."], 400);
        }

        // ✅ Correct OTP — begin transaction
        $conn->begin_transaction();

        try {

            // Mark OTP as used
            $markUsed = $conn->prepare("
            UPDATE otp 
            SET is_used = 1 
            WHERE otp_id = ?
        ");
            $markUsed->bind_param("i", $otpRecord['otp_id']);
            $markUsed->execute();

            // Fetch user info
            $userStmt = $conn->prepare("
            SELECT user_id, username, email
            FROM users
            WHERE user_id = ?
            LIMIT 1
        ");
            $userStmt->bind_param("i", $user_id);
            $userStmt->execute();
            $userResult = $userStmt->get_result();
            $user = $userResult->fetch_assoc();

            if (!$user) {
                throw new Exception("User not found.");
            }

        //     // 🔒 Revoke old refresh tokens for this device
        //     $revoke = $conn->prepare("
        //     UPDATE refresh_tokens
        //     SET revoked = 1
        //     WHERE user_id = ? AND device_id = ?
        // ");
        //     $revoke->bind_param("is", $user_id, $deviceId);
        //     $revoke->execute();

        //     // 🔑 Generate tokens
        //     $accessToken = TokenService::generateAccessToken($user);

        //     $refreshToken = bin2hex(random_bytes(64));
        //     $refreshHash = hash("sha256", $refreshToken);

        //     $expiresAt = date("Y-m-d H:i:s", time() + (7 * 24 * 60 * 60));

        //     // Store refresh token
        //     $insert = $conn->prepare("
        //     INSERT INTO refresh_tokens
        //     (user_id, device_id, token_hash, expiration_time, revoked)
        //     VALUES (?, ?, ?, ?, 0)
        // ");
        //     $insert->bind_param("isss", $user_id, $deviceId, $refreshHash, $expiresAt);
        //     $insert->execute();

            $conn->commit();
            return true;

        } catch (Exception $e) {
            $conn->rollback();
            Response::json(["error" => "OTP verification failed."], 500);
        }
    }


    public static function profile()
    {
        echo json_encode(["message" => "profile"]);
    }

    public static function twoFactorAuthentication()
    {
        $conn = Database::connect();
        $input = Request::json();
        $user_id = (int) ($input['user_id'] ?? 0);
        $otpcode = trim($input['otp_code'] ?? "");
        if (!$user_id || $otpcode === "") {
            Response::json([
                "status" => false,
                "message" => "user_id and otp code is required"
            ]);
        }
        if (!self::verifyOTP()) {
            Response::json([
                "status" => false,
                "message" => "Invalid input"
            ]);
        }
        $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        if (!$user) {
            Response::json([
                "status" => false,
                "message" => "User not found"
            ], 404);
        }

        $accessToken = TokenService::generateAccessToken(
            [
                "user_id" => $user["user_id"],
                "username" => $user["username"],
                "two_factor_verified" => true
            ],
            1800
        );

        $refreshPayload = TokenService::generateRefreshToken();
        $refreshToken = $refreshPayload["token"];

        setcookie("refresh_token", $refreshToken, [
            "expires" => time() + 604800,
            "path" => "/",
            "secure" => true,
            "httponly" => true,
            "samesite" => "None"
        ]);

        Response::json([
            "status" => true,
            "message" => "2FA verified",
            "data" => [
                "access_token" => $accessToken
            ]
        ]);
    }

    public static function getLoginActivity()
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

        // Get latest login per device
        $sql = "
        SELECT 
            d.id,
            d.device_name,
            d.platform,
            d.device_id,
            d.is_trusted,
            d.is_active,
            d.last_seen_at,
            lh.logged_in_time
        FROM devices d
        LEFT JOIN login_histories lh 
            ON lh.device_id = d.device_id
        WHERE d.user_id = ?
        ORDER BY lh.logged_in_time DESC
        LIMIT 20
    ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();

        $sessions = [];

        while ($row = $result->fetch_assoc()) {

            $sessions[] = [
                "id" => $row["id"],
                "device" => $row["device_name"],
                "platform" => $row["platform"],
                "login_time" => $row["logged_in_time"],
                "last_seen" => $row["last_seen_at"],
                "is_trusted" => (bool) $row["is_trusted"],
                "is_active" => (bool) $row["is_active"]
            ];
        }

        Response::json([
            "status" => true,
            "sessions" => $sessions
        ]);
    }

    public static function verifyOTPRoute()
    {
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        $input = Request::json();
        $otp = trim($input["otp"] ?? "");
        $device_id = $input["device_id"] ?? null;

        if (!$user_id) {
            Response::json([
                "status" => false,
                "message" => "Not Authorized"
            ], 401);
            return;
        }

        if (!$otp) {
            Response::json([
                "status" => false,
                "message" => "OTP is required"
            ], 400);
            return;
        }

        // Verify OTP
        $result = self::verifyOTP();

        if (!$result) {
            Response::json([
                "status" => false,
                "message" => "Invalid or expired OTP"
            ], 400);
            return;
        }

        $conn = Database::connect();

        // Get user info again
        $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = ? LIMIT 1");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $userData = $stmt->get_result()->fetch_assoc();

        // Generate final access token
        $accessToken = TokenService::generateAccessToken([
            "user_id" => $userData['user_id'],
            "username" => $userData['username'],
            "two_factor_verified" => true
        ]);

        // Generate refresh token
        $refreshPayload = TokenService::generateRefreshToken();
        $refreshToken = $refreshPayload["token"];
        $refreshHash = $refreshPayload["hash"];

        $expireAt = date("Y-m-d H:i:s", time() + 60 * 60 * 24 * 7);

        $device_id = (string) (Request::input("device_id") ?? null);

        $stmt = $conn->prepare("
        INSERT INTO refresh_tokens (user_id, device_id, token_hash, issued_at, expires_at)
        VALUES (?, ?, ?, NOW(), ?)
    ");
        $stmt->bind_param("isss", $user['user_id'], $device_id, $refreshHash, $expireAt);
        $stmt->execute();

        $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
        setcookie("refresh_token", $refreshToken, [
            "expires" => time() + 60 * 60 * 24 * 7,
            "path" => "/",
            "secure" => $isSecure,
            "httponly" => true,
            "samesite" => $isSecure ? "None" : "Lax"
        ]);

        // Insert login history (important)
        if ($device_id) {

            $stmt = $conn->prepare("
            INSERT INTO login_histories (user_id, device_id, logged_in_time)
            VALUES (?, ?, NOW())
        ");
            $stmt->bind_param("is", $user_id, $device_id);
            $stmt->execute();

            $stmt = $conn->prepare("
            UPDATE devices 
            SET last_seen_at = NOW(), is_active = 1
            WHERE device_id = ?
        ");
            $stmt->bind_param("s", $device_id);
            $stmt->execute();
        }

        Response::json([
            "status" => true,
            "message" => "OTP verification successful",
            "data" => [
                "user_id" => $userData["user_id"],
                "username" => $userData["username"],
                "email" => $userData["email"],
                "display_name" => $userData["display_name"],
                "gender" => $userData["gender"],
                "phone_number" => $userData["phone_number"],
                "profile_image" => $userData["profile_image"],
                "cover_image" => $userData["cover_image"],
                "birthday" => $userData["birthday"],
                "location" => $userData["location"],
                "is_active" => $userData["is_active"],
                "last_seen" => $userData["last_seen"],
                "completed_step" => $userData["completed_step"],
                "access_token" => $accessToken
            ]
        ]);
    }

    public static function getLoggedInDevices()
    {
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        $conn = Database::connect();
        $sql = "SELECT * FROM devices WHERE user_id = ? AND is_active = 1";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);

        $stmt->execute();
        $result = $stmt->get_result();
        $response = [];

        while ($row = $result->fetch_assoc()) {
            $response[] = [
                "device_name" => $row["device_name"],
                "platform" => $row["platform"],
                "last_logged_in" => $row["last_seen_at"],
            ];
        }

        Response::json([
            "status" => true,
            "data" => $response
        ]);
    }

    public static function logoutAllDevices()
    {
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        $device_id = trim(Request::input("device_id") ?? "");

        if (!$user_id) {
            Response::json([
                "status" => false,
                "message" => "Not Authorized"
            ], 400);
            return;
        }

        $conn = Database::connect();
        $sql = "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND device_id != ? AND revoked = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("is", $user_id, $device_id);

        $success = $stmt->execute();
        if ($success) {
            Response::json([
                'status' => true,
                "message" => "Logged out from all other devices"
            ]);
            return;
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to logout from all devices"
            ], 500);
            return;
        }
    }

    public static function sendEmailTest($email, $otpcode)
{
    if (empty($email)) {
        Response::json([
            "status" => false,
            "message" => "Email required"
        ], 400);
        return false;
    }

    $apiKey = $_ENV['BREVO_API_KEY'];
    $sender = $_ENV['BREVO_SENDER'];

    $data = [
        "sender" => [
            "name" => "Yukai Support",
            "email" => $sender
        ],
        "to" => [
            ["email" => $email]
        ],
        "subject" => "Password Reset OTP",
        "htmlContent" => "
            Hello,<br><br>
            Your OTP code is:<br><br>
            <h2>$otpcode</h2>
            This OTP is valid for 5 minutes.<br><br>
            Do not share this code with anyone.<br><br>
            Yukai Support Team
        "
    ];

    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, "https://api.brevo.com/v3/smtp/email");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "accept: application/json",
        "api-key: $apiKey",
        "content-type: application/json"
    ]);

    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        Response::json([
            "status" => false,
            "message" => "Failed to send email",
            "error" => $error
        ], 500);
        return false;
    }

    return true;
}
}