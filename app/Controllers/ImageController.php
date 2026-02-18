<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Request;
use App\Core\Response;
use App\Core\Database;
use App\Service\ImageService;

class ImageController
{
    public static function uploadImage()
    {
        $conn = Database::connect();

        $user = Auth::getUser();
        $user_id = $user["user_id"];

        $folder = Request::file("folder") ?? "chat";

        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid user ID"
            ], 400);
        }

        if (!isset($_FILES['image'])) {
            Response::json([
                "status" => false,
                "message" => "No image uploaded"
            ], 400);
        }

        try {
            // 🔥 Delegate upload to service
            $result = ImageService::uploadImage($_FILES['image'], $folder);

            // Save image URL in database
            // $stmt = $conn->prepare("
            //     UPDATE users 
            //     SET profile_image = :profile_image 
            //     WHERE user_id = :user_id
            // ");

            // $stmt->execute([
            //     ":profile_image" => $result["secure_url"],
            //     ":user_id" => $user_id
            // ]);

            Response::json([
                "status" => true,
                "message" => "Profile image updated successfully",
                "data" => [
                    "image_url" => $result["secure_url"],
                    "storage" => $result["storage"] ?? "cloud"
                ]
            ], 200);

        } catch (\Throwable $e) {
            Response::json([
                "status" => false,
                "message" => "Image upload failed",
                "error" => $e->getMessage()
            ], 500);
        }
    }
}
