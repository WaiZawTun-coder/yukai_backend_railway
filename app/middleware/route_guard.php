<?php

use App\Core\AdminAuth;
use App\Core\JWT;
use App\Core\Auth;

function route_guard()
{
    $headers = getallheaders();

    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["status" => 401, "error" => "Unauthorized"]);
        exit;
    }

    $authHeader = $headers['Authorization'];
    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $token = $matches[1];
    } else {
        http_response_code(401);
        echo json_encode(["error" => "Invalid Authorization Header"]);
        exit;
    }

    try {
        $secret = $_ENV["JWT_SECRET"];
        $decoded = JWT::decode($token, $secret);
        if(isset($decoded["role"]) && ($decoded["role"] == "moderator" || $decoded["role"] == "super_admin")){
            AdminAuth::setAdmin($decoded);
        }else{
        Auth::setUser($decoded);}
        return $decoded;
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid Token", "message" => $e->getMessage()]);
        exit;
    }
}
