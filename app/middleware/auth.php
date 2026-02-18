<?php
use App\Core\JWT;
require_once __DIR__ . "/../bootstrap.php";
require_once __DIR__ . "/../utilities/jwt.php";

$headers = getallheaders();
$auth = $headers['Authorization'] ?? '';

if (!preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
    http_response_code(401);
    echo json_encode(["error" => "Token required"]);
    exit;
}

try {
    $tokenUser = JWT::decode($matches[1], $_ENV['JWT_SECRET']);
    $_REQUEST["user_id"] = $tokenUser["user_id"];
    print_r($tokenUser);
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(["error" => $e->getMessage()]);
    exit;
}