<?php

$allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:8080",
    "https://yukai-social.vercel.app",
    "https://yukai-socket.onrender.com",
    "https://yukai-admin.vercel.app",
    "https://yukaifrontend-production.up.railway.app"
];

if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $allowedOrigins)) {
    header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
}

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . "/../bootstrap.php";
require_once __DIR__ . "/../routes/api.php";
require_once __DIR__ . '/../app/Core/Database.php';
require_once __DIR__ . "/../app/Core/Request.php";
require_once __DIR__ . "/../app/Core/Response.php";
require_once __DIR__ . "/../app/Core/Generator.php";
require_once __DIR__ . "/../app/Core/JWT.php";
require_once __DIR__ . "/../app/Core/Router.php";
require_once __DIR__ . "/../app/Core/Auth.php";
require_once __DIR__ . "/../app/Core/AdminAuth.php";

require_once __DIR__ . "/../app/services/passwordService.php";
require_once __DIR__ . "/../app/services/tokenService.php";
require_once __DIR__ . "/../app/services/imageService.php";
require_once __DIR__ . "/../app/services/emailService.php";

require_once __DIR__ . "/../app/Controllers/AuthController.php";
require_once __DIR__ . "/../app/Controllers/PostController.php";
require_once __DIR__ . "/../app/Controllers/PostHidingController.php";
require_once __DIR__ . "/../app/Controllers/UserController.php";
require_once __DIR__ . "/../app/Controllers/FriendController.php";
require_once __DIR__ . "/../app/Controllers/SearchController.php";
require_once __DIR__ . "/../app/Controllers/SaveController.php";
require_once __DIR__ . "/../app/Controllers/ChatController.php";
require_once __DIR__ . "/../app/Controllers/MessageController.php";
require_once __DIR__ . "/../app/Controllers/ReportController.php";
require_once __DIR__ . "/../app/Controllers/AdminController.php";
require_once __DIR__ . "/../app/Controllers/DeviceController.php";
require_once __DIR__ . "/../app/Controllers/NotificationController.php";
require_once __DIR__ . "/../app/Controllers/ImageController.php";
require_once __DIR__ . "/../app/Controllers/DashboardController.php";
require_once __DIR__ . "/../app/Controllers/PrivacyController.php";

Router::dispatch();


