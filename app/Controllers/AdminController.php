<?php



namespace App\Controllers;

use App\Core\AdminAuth;
use App\Core\Request;
use App\Core\Response;
use App\Core\Database;
use App\Core\Generator;
use App\Service\EmailService;
use App\Service\ImageService;
use App\Service\TokenService;

use App\Service\PasswordService;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../../phpmailer/Exception.php';
require_once __DIR__ . '/../../phpmailer/PHPMailer.php';
require_once __DIR__ . '/../../phpmailer/SMTP.php';

class AdminController
{

    /* ====== Account Status ====== */
    public static function updateAccountStatus()
    {
        $admin_id = (int) (Request::input("admin_id") ?? 0);
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $status = trim(Request::input("status") ?? "");

        /* ===== check admin exist ====*/
        $sql = "SELECT * FROM admin WHERE admin_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $admin_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Admin not found"
            ], 404);
            return;
        }


        /* ===== check user exist ====*/
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
            return;
        }

        $update = $conn->prepare("UPDATE users SET status= ? WHERE user_id=?");
        $update->bind_param("si", $status, $user_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "Status changed successful"
            ], 200);
        } else {
            Response::json([
                "status" => false,
                "message" => "Failed to update status"
            ], 500);
        }


    }


    /* ================ Get All Admin List ================ */
    public static function getAdminLists()
    {
        $conn = Database::connect();
        // Current page
        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
        $limit = 5;
        $offset = ($page - 1) * $limit;

        /* ---------- COUNT TOTAL ROWS ---------- */
        $countStmt = $conn->prepare("SELECT COUNT(*) as total FROM admin ");
        $countStmt->execute();
        $countResult = $countStmt->get_result()->fetch_assoc();

        $totalRecords = (int) $countResult['total'];
        $totalPages = ceil($totalRecords / $limit);

        if ($totalRecords === 0) {
            Response::json([
                "status" => false,
                "message" => "Admin Account is not found"
            ]);
            return;
        }

        /* ---------- FETCH DATA ---------- */
        $stmt = $conn->prepare(
            "SELECT ad.username,
                ad.display_name,
                ad.email,
                ad.profile_image,
                ad.role,
                ad.admin_id,
                ad.is_active

                FROM admin ad
                LIMIT ? OFFSET ?"
        );

        $stmt->bind_param("ii", $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();

        $adminAccounts = [];
        while ($row = $result->fetch_assoc()) {
            $adminAccounts[] = $row;
        }

        /* ---------- RESPONSE ---------- */
        Response::json([
            "status" => true,
            "current_page" => $page,
            "limit" => $limit,
            "total_pages" => $totalPages,
            "total_records" => $totalRecords,
            "data" => $adminAccounts
        ]);

    }

    // =====================================
    // Ban Morderator from admin
    // =====================================

    public static function banAdmin()
    {
        $conn = Database::connect();
        $admin = AdminAuth::admin();
        $super_admin_id = $admin["admin_id"];
        $banned_admin_id = (int) (Request::input("banned_admin_id") ?? 0);

        if ($super_admin_id <= 0 || $banned_admin_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid ID"
            ]);
            return;
        }
        // super admin cannot ban himself
        if ($super_admin_id === $banned_admin_id) {
            Response::json([
                "status" => false,
                "message" => "Admin cannot ban own account"
            ]);
            return;
        }

        $stmt = $conn->prepare("SELECT * FROM admin WHERE admin_id=? and role='super_admin' and is_active=1");
        $stmt->bind_param("i", $super_admin_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Only super admin can ban other admins"
            ]);
            return;
        }

        // ban admin 

        $update = $conn->prepare("UPDATE admin SET is_active = 0 WHERE admin_id=? ");
        $update->bind_param("i", $banned_admin_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "Banned Successfully"
            ]);
            return;
        } else {
            Response::json([
                "status" => false,
                "message" => " Admin Account cannot be banned "
            ]);
        }
    }

    public static function unbanAdmin()
    {
        $conn = Database::connect();
        $admin = AdminAuth::admin();
        $super_admin_id = $admin["admin_id"];
        $banned_admin_id = (int) (Request::input("banned_admin_id") ?? 0);

        if ($super_admin_id <= 0 || $banned_admin_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid ID"
            ]);
            return;
        }
        // super admin cannot ban himself
        if ($super_admin_id === $banned_admin_id) {
            Response::json([
                "status" => false,
                "message" => "Super admin cannot be unbanned himself"
            ]);
            return;
        }

        $stmt = $conn->prepare("SELECT * FROM admin WHERE admin_id=? and role='super_admin' and is_active=1");
        $stmt->bind_param("i", $super_admin_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Only super admin can ban or unban other admins"
            ]);
            return;
        }

        // ban admin 

        $update = $conn->prepare("UPDATE admin SET is_active = 1 WHERE admin_id=? ");
        $update->bind_param("i", $banned_admin_id);

        if ($update->execute()) {
            Response::json([
                "status" => true,
                "message" => "Unbanned Successfully"
            ]);
            return;
        } else {
            Response::json([
                "status" => false,
                "message" => " Admin Account cannot be banned "
            ]);
        }
    }


    public static function AdminRegister()
    {
        $conn = Database::connect();
        $input = Request::json();
        $displayUsername = trim($input['displayName'] ?? '');
        $email = trim($input['email'] ?? '');

        $creator = AdminAuth::admin();

        if (!$creator) {
            return Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], status: 401);
        }

        $creator_role = $creator['role'] ?? null;
        if (!$creator || $creator_role !== 'super_admin') {
            Response::json([
                "status" => false,
                "message" => "Only Super Admin can create admin accounts"
            ]);
        }

        //to test field requirements
        if ($displayUsername === "" || $email === "") {
            Response::json(["status" => false, "message" => "All fields required"], 400);
        }
        EmailService::validate($email);

        //to test email already exists or not??
        $stmt = $conn->prepare("SELECT admin_id FROM admin WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            Response::json(["status" => false, "message" => "Email already registered"], 409);
        }
        $generatedUsername = Generator::generateUsername($displayUsername);
        // $hashpwd = null;
        $super_admin_id = (int) $creator['admin_id'];

        $sql = "INSERT INTO admin (username, display_name, email, created_by)
            VALUES (?, ?, ?, ?)";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param(
            "sssi",
            $generatedUsername,
            $displayUsername,
            $email,
            $super_admin_id
        );

        $stmt->execute();
        $result = $stmt->get_result();
        $admin_id = $conn->insert_id;

        Response::json([
            "status" => true,
            "message" => "Admin created successfully.Password has not set yet",
            "created by" => $creator_role,
            "data" => [
                "admin_id" => $admin_id,
                "username" => $generatedUsername,
                "display_name" => $displayUsername,
                "email" => $email,
                "role" => "admin",
                "is_active" => 1
            ]
        ], 201);

    }

    public static function AdminLogin()
    {
        $conn = Database::connect();
        $input = Request::json();

        $username = trim($input['username'] ?? '');//login
        $password = trim($input['password'] ?? null);


        if ($username === '') {
            Response::json([
                "status" => false,
                "message" => "Username required"

            ], 400);
            return;
        }

        $sql = "SELECT * FROM admin

                WHERE email = ? OR username = ?
                LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $username, $username);

        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Account not found"
            ], 404);
            return;
        }
        $user = $result->fetch_assoc();

        if ($user['password'] === null) {

            $otp = self::generateOTP($user['admin_id']);
            self::sendEmail($user['email'], $otp);

            Response::json([
                "status" => true,
                "message" => "Password was not set. OTP sent to email.",
                "action" => "SET_PASSWORD"
            ]);

        }


        // //password verify
        if (!PasswordService::verify($password, $user['password'])) {
            Response::json([
                "status" => false,
                "message" => "Incorrect password"
            ]);
        }


        if ((int) $user['is_active'] === 0) {
            Response::json([
                "status" => false,
                "message" => "Inactive admin account"
            ], 403);
            return;
        }



        $accessToken = TokenService::generateAccessToken([
            "admin_id" => $user['admin_id'],
            "username" => $user['username'],
            "role" => $user["role"],
        ]);

        $isSecure =
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

        $refreshPayload = TokenService::generateRefreshToken();
        $refreshToken = $refreshPayload["token"];
        $refreshHash = $refreshPayload["hash"];
        $refreshExpire = date("Y-m-d H:i:s", time() + 604800); // 7 days

        $stmt = $conn->prepare("
            INSERT INTO admin_refresh_tokens(admin_id, refresh_token, expires_at)
            VALUES (?, ?, ?)
        ");

        $stmt->bind_param("iss", $user["admin_id"], $refreshHash, $refreshExpire);
        $stmt->execute();

        setcookie("refresh_token", $refreshToken, [
            "expires" => time() + 604800, // 7 days
            "path" => "/",
            "secure" => $isSecure,
            "httponly" => true,
            "samesite" => $isSecure ? "None" : "Lax"
        ]);

        Response::json([
            "status" => true,
            "message" => "Login successful",
            "data" => [

                // "admin_user_id"      => $user["user_id"],
                "username" => $user["username"],
                "email" => $user["email"],
                "role" => $user['role'],
                "display_name" => $user["display_name"],
                "is_active" => $user["is_active"],
                "last_seen" => $user["last_seen"],
                "access_token" => $accessToken,

            ]
        ]);
    }

    public static function setPassword(){
        $conn = Database::connect();

        $email = trim(Request::input("email") ?? "");

        if(empty($email)){
            Response::json([
                "status" => false,
                "message" => "Unknown user"
            ], 400);
            return;
        }

        $otp = trim(Request::input("otp") ?? "");
        if(empty($otp)){
            Response::json([
                "status" => false,
                "message" => "OTP code is required"
            ], 400);
            return;
        }

        $password = trim(Request::input("password") ?? "");
        if(empty($password)){
            Response::json([
                "status" => false,
                "message" => "Password cannot be empty"
            ], 400);
            return;
        }

        $getUserIdSql = "SELECT admin_id FROM admin WHERE email = ? OR username = ? AND is_active = 1";
        $stmt = $conn->prepare($getUserIdSql);
        $stmt->bind_param("ss",$email, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $adminId = $result->fetch_assoc()["admin_id"] ?? 0;

        if($adminId == 0){
            Response::json([
                "status" => false,
                "message" => "User not found or is banned"
            ], 404);
            return;
        }

        PasswordService::isStrong($password);

        if(!self::verifyOTP($adminId, $otp)){
            Response::json([
                "status" => false,
                "message" => "Invalid or expired OTP"
            ], 400);
            return;
        }

        $hashedPassword = PasswordService::hash($password);
        $stmt = $conn->prepare("UPDATE admin SET password = ? WHERE admin_id = ?");
        $stmt->bind_param("si", $hashedPassword, $adminId);
        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Password updated successfully please login with new password"
            ]);
            return;
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to set password"
            ], 500);
        }
        
    }


    public static function generateOTP($admin_id)
    {
        $conn = Database::connect();


        $otpcode = '';
        for ($i = 0; $i < 8; $i++) {
            $otpcode .= random_int(0, 9);
        }
        $expiryMinutes = 5;

        $hashedOtp = password_hash($otpcode, PASSWORD_DEFAULT);

        // Clean up existing OTPs for this user
        $cleanupStmt = $conn->prepare("
                DELETE FROM admin_otp 
                WHERE admin_id = ?
            ");
        $cleanupStmt->bind_param("i", $admin_id);
        $cleanupStmt->execute();

        // Insert new OTP record (NOT USED YET)
        $stmt = $conn->prepare("
                INSERT INTO admin_otp (admin_id, otp_code, expiration_time)
                VALUES (?, ?, NOW() + INTERVAL 5 MINUTE);
            ");
        $stmt->bind_param("is", $admin_id, $hashedOtp);

        if (!$stmt->execute()) {
            return false;

        }

        // Response::json([
        //     "status" => true,
        //     "message" => "Added Successfully",
        //     "data" => [
        //         // "otp code"=>$otpcode,
        //         "otp_id" => $conn->insert_id,
        //         "expires_in_minutes" => $expiryMinutes,
        //         "otp-code"=>$otpcode
        //     ]
        // ]);
        return $otpcode;
    }


    // Verify OTP
    public static function verifyOTP($admin_id, $otpcode)
    {
        $conn = Database::connect();


        // Get valid OTPs for this user
        $stmt = $conn->prepare("
                SELECT otp_id, otp_code, expiration_time
                FROM admin_otp
                WHERE admin_id = ? 
                AND expiration_time > NOW()
                AND is_used = FALSE
                ORDER BY created_at DESC
                LIMIT 1
            ");
        $stmt->bind_param("i", $admin_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                'status' => false,
                'message' => 'No valid OTP found or OTP has expired'
            ], 400);
        }

        $otpRecord = $result->fetch_assoc();
        if (!password_verify($otpcode, $otpRecord['otp_code'])) {
            Response::json([
                'status' => false,
                'message' => 'Invalid OTP code'
            ], 401);
        }

        // Mark OTP as used
        $updateStmt = $conn->prepare("
                UPDATE admin_otp
                SET is_used = TRUE
                WHERE otp_id = ?
            ");
        $updateStmt->bind_param("i", $otpRecord['otp_id']);
        $updateStmt->execute();

        // Response::json([
        //     'status' => true,
        //     'message' => 'OTP verified successfully'
        // ]);
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

        $stmt = $conn->prepare("SELECT admin_id, role FROM admin WHERE email = ? AND is_active=1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        if (!$user) {
            Response::json([
                "status" => false,
                "message" => "User not found or is banned"
            ], 404);
        }

        if ($user['role'] === 'super_admin') {
            Response::json([
                "status" => false,
                "message" => "Super Admin cannot reset his own password"
            ]);
        }

        $otpcode = self::generateOTP($user['admin_id']);

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
    public static function resetPassword()
    {
        $conn = Database::connect();

        $admin_id = (int) (Request::input("admin_id") ?? 0);
        $otpcode = trim(Request::input("otp_code") ?? "");
        $newPassword = Request::input("new_password") ?? "";

        if (!$admin_id || $otpcode === "" || $newPassword === "") {
            Response::json([
                "status" => false,
                "message" => "All fields are required"
            ], 400);
        }

        if (!self::verifyOTP($admin_id, $otpcode)) {
            Response::json([
                "status" => false,
                "message" => "Invalid or expired OTP"
            ], 401);
        }
        PasswordService::isStrong($newPassword);
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("UPDATE admin SET password = ? WHERE admin_id = ?");
        $stmt->bind_param("si", $hashedPassword, $admin_id);
        $stmt->execute();

        Response::json([
            "status" => true,
            "message" => "Password reset successfully"
        ]);
    }
    //banned user
    public static function banUser()
    {
        $conn = Database::connect();
        $input = Request::json();
        $user_id = (int) ($input['user_id'] ?? 0);
        $admin = AdminAuth::admin();
        error_log("Admin data: " . print_r($admin, true));

        if (!$admin) {
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ]);
            return;

        }

        // Allow only admin or super_admin
        if (!in_array($admin['role'], ['admin', 'super_admin'])) {
            Response::json([
                "status" => false,
                "message" => "Forbidden: Only admin or super admin can ban users"
            ]);
            return;

        }

        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ]);
        }
        $userSql = "SELECT user_id, is_active from users where user_id=?";
        $userStmt = $conn->prepare($userSql);
        $userStmt->bind_param("i", $user_id);
        $userStmt->execute();
        $user = $userStmt->get_result()->fetch_assoc();
        if (!$user) {
            Response::json([
                "status" => false,
                "message" => "user does not exist"
            ]);
        }
        if ((int) $user['is_active'] === 0) {
            Response::json([
                "status" => false,
                "message" => "This user is aleady banned"
            ]);
        }
        $updateBanUserSql = "UPDATE users set is_active=0 WHERE user_id=?";
        $updateBanUser = $conn->prepare($updateBanUserSql);
        $updateBanUser->bind_param("i", $user_id);
        $updateBanUser->execute();
        Response::json([
            "status" => true,
            "message" => "ban user successfully",
            "role" => $admin
        ]);

    }
    public static function banPost()
    {
        $conn = Database::connect();
        $input = Request::json();
        $post_id = (int) ($input['post_id'] ?? 0);
        $admin = AdminAuth::admin();
        error_log("Admin data: " . print_r($admin, true));

        if (!$admin) {
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ]);
            return;

        }

        // Allow only admin or super_admin
        if (!in_array($admin['role'], ['admin', 'super_admin'])) {
            Response::json([
                "status" => false,
                "message" => "Forbidden: Only admin or super admin can ban users"
            ]);
            return;

        }

        if ($post_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post"
            ]);
        }
        $postSql = "SELECT post_id, is_banned from posts where post_id=?";
        $poststmt = $conn->prepare($postSql);
        $poststmt->bind_param("i", $post_id);
        $poststmt->execute();
        $post = $poststmt->get_result()->fetch_assoc();
        if (!$post) {
            Response::json([
                "status" => false,
                "message" => "post does not exist"
            ]);
        }
        if ((int) $post['is_banned'] === 1) {
            Response::json([
                "status" => false,
                "message" => "this post is already banned"
            ]);
        }
        $postBanSql = "UPDATE posts SET is_banned=1 WHERE post_id=?";
        $postBan = $conn->prepare($postBanSql);
        $postBan->bind_param("i", $post_id);
        $postBan->execute();
        Response::json([
            "status" => true,
            "message" => "ban post successfully",
            "role" => $admin
        ]);

    }

    public static function unbanPost(){
        $conn = Database::connect();
        $input = Request::json();
        $post_id = (int) ($input['post_id'] ?? 0);
        $admin = AdminAuth::admin();
        error_log("Admin data: " . print_r($admin, true));

        if (!$admin) {
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ]);
            return;

        }

        // Allow only admin or super_admin
        if (!in_array($admin['role'], ['admin', 'super_admin'])) {
            Response::json([
                "status" => false,
                "message" => "Forbidden: Only admin or super admin can unban posts"
            ]);
            return;

        }

        if ($post_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post"
            ]);
        }
        $postSql = "SELECT post_id, is_banned from posts where post_id=?";
        $poststmt = $conn->prepare($postSql);
        $poststmt->bind_param("i", $post_id);
        $poststmt->execute();
        $post = $poststmt->get_result()->fetch_assoc();
        if (!$post) {
            Response::json([
                "status" => false,
                "message" => "post does not exist"
            ]);
        }
        if ((int) $post['is_banned'] === 0) {
            Response::json([
                "status" => false,
                "message" => "this post is not banned"
            ]);
        }
        $postUnbanSql = "UPDATE posts SET is_banned=0 WHERE post_id=?";
        $postUnban = $conn->prepare($postUnbanSql);
        $postUnban->bind_param("i", $post_id);
        $postUnban->execute();
        Response::json([
            "status" => true,
            "message" => "unban post successfully",
            "role" => $admin
        ]);
    }

    //user profile edit
    public static function editAdminProfile()
    {

        $conn = Database::connect();
        // $current_admin=AdminAuth::admin();
        //  if (!$current_admin) {
        //      Response::json([
        //      "status"=>false,
        //      "message"=>"unauthorized"
        //     ], 401);
        //     return; 
        //   }

        $admin = AdminAuth::admin();
        $admin_id = (int) ($admin["admin_id"] ?? 0);

        if($admin_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Unauthorized admin"
            ]);
        }

        $display_name = trim(Request::input("display_name") ?? "");
        $username = trim(Request::input("username") ?? "");
        $email = trim(Request::input("email") ?? "");
        $profile_image = Request::file("profile_image") ?? null;
        // $password = trim(Request::input('password') ?? "");
        //Authorization::Only admins can only edit their own profile
        // if($current_admin['admin_id']!==$admin_id){
        //     Response::json([
        //         "status"=>false,
        //         "message"=>"You can only edit your own profile"
        //     ]);
        // }

        // Check admin exists
        $sql = "SELECT * FROM admin WHERE admin_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $admin_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Admin not found"
            ], 404);
            return;
        }


        $admin = $result->fetch_assoc();
        $updates = [];
        $params = [];
        $types = "";

        // =====================================
        // NORMAL PROFILE UPDATES
        // =====================================

        if (!empty($display_name)) {
            $current_display_name = trim($admin['display_name'] ?? '');

            if (strtolower($display_name) !== strtolower($current_display_name)) {
                // Display name is changing, check if new one already exists
                $checkDisplayNameSql = "SELECT admin_id FROM admin WHERE LOWER(display_name) = ? AND admin_id != ?";
                $checkStmt = $conn->prepare($checkDisplayNameSql);
                $normalized_display_name = strtolower($display_name);
                $checkStmt->bind_param("si", $normalized_display_name, $admin_id);
                $checkStmt->execute();

                if ($checkStmt->get_result()->num_rows > 0) {
                    Response::json([
                        "status" => false,
                        "message" => "Display name already exists"
                    ], 400);
                    return;
                }
            }
            $updates[] = "display_name = ?";
            $params[] = $display_name;
            $types .= "s";
        }
        if (!empty($email)) {
            EmailService::validate($email);
            if ($email !== $admin['email']) {
                // Check if new email already exists for another admin
                $checkEmailSql = "SELECT admin_id FROM admin WHERE email = ? AND admin_id != ?";
                $checkStmt = $conn->prepare($checkEmailSql);
                $checkStmt->bind_param("si", $email, $admin_id);
                $checkStmt->execute();
                $emailResult = $checkStmt->get_result();

                if ($emailResult->num_rows > 0) {
                    Response::json([
                        "status" => false,
                        "message" => "Email already exists"
                    ], 400);

                }
            }
            $updates[] = "email = ?";
            $params[] = $email;
            $types .= "s";
        }
        // if (!empty($password)) {
        //     PasswordService::isStrong($password);
        //     $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        //     $updates[] = "password = ?";
        //     $params[] = $hashedPassword;
        //     $types .= "s";
        // }

        if (!empty($profile_image)) {
            $imageUploadResult = ImageService::uploadImage($profile_image);
            $secure_url = $imageUploadResult["secure_url"] ?? "";

            if($secure_url == ""){
                Response::json([
                    "status" => false,
                    "message" => "Failed to upload profile image."
                ]);
            }

            $updates[] = "profile_image = ?";
            $params[] = $secure_url;
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



        $params[] = $admin_id;
        $types .= "i";

        $sql = "UPDATE admin SET " . implode(" ,", $updates) . " WHERE admin_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$params);

        if ($stmt->execute()) {
            if ($stmt->affected_rows > 0) {
                Response::json([
                    "status" => true,
                    "message" => "Admin updated successfully",
                    "data" => [
                        "admin_id" => $admin_id,
                        "display_name" => $display_name ?: $admin["display_name"],
                        "email" => $email ?: $admin["email"],
                        "profile_image" => $secure_url ?? $admin["profile_image"]
                    ]
                ], 200);
            } else {
                Response::json([
                    "status" => false,
                    "message" => "No changes were made"
                ], 200);
            }
        }
    }

    public static function checkAdminPassword(){
        $conn = Database::connect();

        $admin = AdminAuth::admin();
        $admin_id = (int) ($admin["admin_id"] ?? 0);
        $password = trim(Request::input("password") ?? "");

        if($admin_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Unauthorized admin"
            ], 401);
        }

        if(empty($password)){
            Response::json([
                "status" => false,
                "message" => "Password is required"
            ], 400);
        }

        $sql = "SELECT password FROM admin WHERE admin_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $admin_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if($result->num_rows == 0){
            Response::json([
                "status" => false,
                "message" => "Admin not found"
            ], 404);
        };

        $row = $result->fetch_assoc();
        if($row["password"] == null){
            Response::json([
                "status" => false,
                "message" => "Password not set for this admin"
            ], 400);
        }

        if(PasswordService::verify($password, $row["password"])){
            Response::json([
                "status" => true,
                "message" => "Password is correct"
            ]);
        }

        Response::json([
            "status" => false,
            "message" => "Incorrect password"
        ], 400);
    }

    public static function updateAdminPassword(){
        $conn = Database::connect();
        $admin = AdminAuth::admin();
        
        if(!$admin){
            Response::json([
                "status" => false,
                "message" => "Unauthorized admin"
            ], 400);
        }
        $admin_id = (int) ($admin["admin_id"] ?? 0);

        $newPassword = trim(Request::input("new_password") ?? "");

        if(empty($newPassword)){
            Response::json([
                "status" => false,
                "message" => "New password is required"
            ], 400);
        }

        $hashNewPassword = PasswordService::hash($newPassword);

        $sql = "UPDATE admin SET password = ? WHERE admin_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $hashNewPassword, $admin_id);

        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Password updated successfully"
            ]);
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to update password"
            ], 500);
        }
    }

    public static function refresh()
    {
        $conn = Database::connect();

        $isSecure =
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

        $refreshToken = $_COOKIE["refresh_token"] ?? null;

        if (!$refreshToken) {
            Response::json([
                "status" => false,
                "message" => "Refresh token missing"
            ], 401);
            return;
        }

        $refreshHash = hash("sha256", $refreshToken);

        $stmt = $conn->prepare("SELECT art.token_id, art.admin_id, art.expires_at, a.username, a.role, a.is_active FROM admin_refresh_tokens art JOIN admin a ON a.admin_id = art.admin_id WHERE art.refresh_token = ? AND art.revoked = 0 LIMIT 1
        ");

        $stmt->bind_param("s", $refreshHash);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows == 0) {
            // Invalid token
            setcookie("refresh_token", "", [
                "expires" => time() - 3600,
                "path" => "/",
                "secure" => $isSecure,
                "httponly" => true,
                "samesite" => $isSecure ? "None" : "Lax"
            ]);

            Response::json([
                "status" => false,
                "message" => "Invalid refresh token"
            ], 401);
        }

        $tokenData = $result->fetch_assoc();

        $checkAdminSql = "SELECT is_active FROM admin WHERE admin_id = ?";
        $stmt = $conn->prepare($checkAdminSql);
        $stmt->bind_param("i", $tokenData['admin_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $is_active = $result->fetch_assoc()["is_active"];

        if ($is_active == 0) {
            Response::json([
                "status" => false,
                "message" => "This admin is banned"
            ], 400);
        }


        if (strtotime($tokenData["expires_at"]) < time()) {
            $stmt = $conn->prepare("UPDATE admin_refresh_tokens SET revoked = 1 WHERE token_id = ?");
            $stmt->bind_param("i", $tokenData["token_id"]);
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
        }

        $refreshPayload = TokenService::generateRefreshToken();
        $newRefreshToken = $refreshPayload["token"];
        $newRefreshHash = $refreshPayload["hash"];
        $newExpire = date("Y-m-d H:i:s", time() + 604800);

        $stmt = $conn->prepare("INSERT INTO admin_refresh_tokens(admin_id, refresh_token, expires_at) VALUES (?, ?, ?)
        ");

        $stmt->bind_param("iss", $tokenData["admin_id"], $newRefreshHash, $newExpire);
        $stmt->execute();

        $stmt = $conn->prepare("UPDATE admin_refresh_tokens SET revoked = 1 WHERE token_id = ?");
        $stmt->bind_param("i", $tokenData["token_id"]);
        $stmt->execute();

        setcookie("refresh_token", $newRefreshToken, [
            "expires" => time() + 604800,
            "path" => "/",
            "secure" => $isSecure,
            "httponly" => true,
            "samesite" => $isSecure ? "None" : "Lax"
        ]);

        $accessToken = TokenService::generateAccessToken([
            "admin_id" => $tokenData["admin_id"],
            "username" => $tokenData["username"],
            "role" => $tokenData["role"]
        ]);

        Response::json([
            "status" => true,
            "message" => "Token refreshed",
            "data" => [
                "access_token" => $accessToken
            ]
        ]);
    }

    public static function getProfile()
    {
        $conn = Database::connect();
        $admin = AdminAuth::admin();

        if(!$admin){
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], 401);
        }

        $adminId = $admin["admin_id"];


        // Fetch admin data
        $stmt = $conn->prepare("
        SELECT admin_id, username, email, display_name, role, is_active, last_seen, profile_image
        FROM admin
        WHERE admin_id = ?
        LIMIT 1
    ");

        $stmt->bind_param("i", $adminId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Admin not found"
            ], 404);
            return;
        }

        $user = $result->fetch_assoc();

        Response::json([
            "status" => true,
            "message" => "Profile fetched",
            "data" => $user
        ]);
    }

    public static function logout()
    {
        $conn = Database::connect();

        $admin = AdminAuth::admin();
        $admin_id = $admin["admin_id"];

        $sql = "UPDATE admin_refresh_tokens SET revoked = 1 WHERE admin_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $admin_id);
        $stmt->execute();


        Response::json([
            "status" => true,
            "message" => "Logged out successful"
        ]);
    }

    public static function getUsers()
    {
        $conn = Database::connect();

        $admin = AdminAuth::admin();
        $admin_id = $admin["admin_id"];

        if (!$admin_id) {
            Response::json([
                "status" => false,
                "message" => "Not authorized"
            ], 400);
            return;
        }

        // Get pagination params
        [$page, $limit, $offset] = self::getPageParams();

        // Get search param from query string (optional)
        $search = isset($_GET['search']) ? trim($_GET['search']) : '';

        // Base SQL
        $sql = "SELECT user_id, username, display_name, gender, profile_image, is_active, status FROM users";
        $params = [];
        $types = "";

        // Add search filter if provided
        if ($search !== '') {
            $sql .= " WHERE username LIKE ? OR display_name LIKE ? OR CAST(user_id AS CHAR) LIKE ?";
            $searchTerm = "%{$search}%";
            $params = [$searchTerm, $searchTerm, $searchTerm];
            $types = "sss"; // all string types
        }

        // Add LIMIT/OFFSET
        $sql .= " LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        $types .= "ii"; // integer types for limit/offset

        $stmt = $conn->prepare($sql);

        // Bind parameters dynamically
        $stmt->bind_param($types, ...$params);

        $stmt->execute();
        $result = $stmt->get_result();
        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = [
                "user_id" => $row["user_id"],
                "username" => $row["username"],
                "display_name" => $row["display_name"],
                "gender" => $row["gender"],
                "profile_image" => $row["profile_image"],
                "is_active" => $row["is_active"],
                "status" => $row["status"]
            ];
        }

        // Get total count (for pagination)
        $countSql = "SELECT COUNT(*) as total_user FROM users";
        if ($search !== '') {
            $countSql .= " WHERE username LIKE ? OR display_name LIKE ? OR CAST(user_id AS CHAR) LIKE ?";
            $stmtCount = $conn->prepare($countSql);
            $stmtCount->bind_param("sss", $searchTerm, $searchTerm, $searchTerm);
        } else {
            $stmtCount = $conn->prepare($countSql);
        }
        $stmtCount->execute();
        $resultCount = $stmtCount->get_result();
        $count = $resultCount->fetch_assoc()["total_user"];

        Response::json([
            "status" => true,
            "page" => $page,
            "total_pages" => ceil($count / $limit),
            "data" => $users,
            "limit" => $limit
        ]);
    }

    public static function unbanUser(){
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $admin = AdminAuth::admin();
        if(!$admin){
            Response::json([
                "status" => false, 
                "message" => "Unauthorized"
            ]);
        }

        if($user_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
        }

        $admin_id = $admin["admin_id"];

        $sql = "UPDATE users SET is_active = 1 WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);

        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Unbanned successfully"
            ]);
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to unban user"
            ], 500);
        }
    }

    public static function warnUser(){
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $admin = AdminAuth::admin();
        if(!$admin){
            Response::json([
                "status" => false, 
                "message" => "Unauthorized"
            ]);
        }

        if($user_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
        }

        $admin_id = $admin["admin_id"];

        $sql = "UPDATE users SET status = 'warn_user' WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);

        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Warned user successfully"
            ]);
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to warn user"
            ], 500);
        }
    }

    public static function removeWarnUser(){
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $admin = AdminAuth::admin();
        if(!$admin){
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], 401);
            return;
        }

        if($user_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
        }

        $admin_id = $admin["admin_id"];

        $sql = "UPDATE users SET status = 'healthy' WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        
        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Unwarned user successfully"
            ]);
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to unwarn user"
            ], 500);
        }
    }

    public static function suspendUser(){
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $admin = AdminAuth::admin();
        if(!$admin){
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], 401);
            return;
        }

        if($user_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
        }

        $admin_id = $admin["admin_id"];

        $sql = "UPDATE users SET status = 'suspend_user' WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        
        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Suspended user successfully"
            ]);
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to suspend user"
            ], 500);
        }
    }

    public static function unsuspendUser(){
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $admin = AdminAuth::admin();
        if(!$admin){
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], 401);
            return;
        }

        if($user_id <= 0){
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
        }

        $admin_id = $admin["admin_id"];

        $sql = "UPDATE users SET status = 'healthy' WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        
        if($stmt->execute()){
            Response::json([
                "status" => true,
                "message" => "Unsuspended user successfully"
            ]);
        }else{
            Response::json([
                "status" => false,
                "message" => "Failed to unsuspend user"
            ], 500);
        }
    }

    public static function getReportedPosts(){
        $conn = Database::connect();
        $admin = AdminAuth::admin();

        if(!$admin){
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], 401);
            return;
        }

        // Get pagination params
        [$page, $limit, $offset] = self::getPageParams();

        $sql = "SELECT r.id, r.post_id, r.report_reason, r.created_at, p.content, p.is_banned FROM reported_posts r JOIN posts p ON r.post_id = p.post_id ORDER BY r.created_at DESC LIMIT ? OFFSET ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();
        $reports = [];
        while($row = $result->fetch_assoc()){
            $reports[] = [
                "report_id" => $row["report_id"],
                "post_id" => $row["post_id"],
                "report_reason" => $row["report_reason"],
                "created_at" => $row["created_at"],
                "content" => $row["content"],
                "is_banned" => $row["is_banned"]
            ];
        }

        // Get total count for pagination
        $countSql = "SELECT COUNT(*) as total_reports FROM reports";
        $countStmt = $conn->prepare($countSql);
        $countStmt->execute();
        $countResult = $countStmt->get_result();
        $totalReports = $countResult->fetch_assoc()["total_reports"];

        Response::json([
            "status" => true,
            "page" => $page,
            "total_pages" => ceil($totalReports / $limit),
            "data" => $reports,
            "limit" => $limit
        ]);
    }

    public static function updateReportStatus(){
    $conn = Database::connect();
    $admin = AdminAuth::admin();

    if(!$admin){
        Response::json([
            "status" => false,
            "message" => "Unauthorized"
        ], 401);
        return;
    }

    $report_id = (int) (Request::input("report_id") ?? 0);
    $status = trim(Request::input("status") ?? "");

    if($report_id <= 0 || !in_array($status, ['pending', 'reviewed', 'removed'])){
        Response::json([
            "status" => false,
            "message" => "Invalid report ID or status"
        ], 400);
        return;
    }

    try {
        // Start transaction
        $conn->begin_transaction();

        // 1️⃣ Update report status
        $sql = "UPDATE reported_posts SET status = ? WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $status, $report_id);

        if(!$stmt->execute()){
            throw new Exception("Failed to update report");
        }

        // 2️⃣ If status is 'removed', ban the related post
        if($status === 'removed'){
            $sql = "UPDATE posts p 
                    JOIN reported_posts r ON p.post_id = r.post_id 
                    SET p.is_banned = 1 
                    WHERE r.id = ?";
                    
            $banStmt = $conn->prepare($sql);
            $banStmt->bind_param("i", $report_id);

            if(!$banStmt->execute()){
                throw new Exception("Failed to ban post");
            }
        }

        // Commit if everything is successful
        $conn->commit();

        Response::json([
            "status" => true,
            "message" => "Report status updated successfully"
        ]);

    } catch (Exception $e) {
        // Rollback on error
        $conn->rollback();

        Response::json([
            "status" => false,
            "message" => "Transaction failed: " . $e->getMessage()
        ], 500);
    }
}

    private static function getPageParams()
    {
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $limit = 15;
        $offset = ($page - 1) * $limit;

        return [$page, $limit, $offset];
    }
}

