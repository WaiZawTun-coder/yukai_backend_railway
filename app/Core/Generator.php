<?php
namespace App\Core;

class Generator{
    public static function generateUsername($name){
        $conn = Database::connect();
        do{
            $username = strtolower($name) . rand(1000, 9999);
            $username =  preg_replace('/\s+/', '', $username);
            $checkUsernameSql = "SELECT username FROM users WHERE username = ?";
            $checkUsernameStmt = $conn->prepare($checkUsernameSql);
            $checkUsernameStmt->bind_param("s", $username);
            $checkUsernameStmt->execute();
            $result = $checkUsernameStmt->get_result();
        }while($result->num_rows > 0);

        return $username;
    }
}