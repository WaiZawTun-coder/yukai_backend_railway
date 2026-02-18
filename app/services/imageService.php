<?php

namespace App\Service;

use App\Core\Response;
use CURLFile;

class ImageService
{
    public static function uploadImage($file, $folder = "profiles")
    {
        if (!isset($file["tmp_name"]) || !file_exists($file["tmp_name"])) {
            Response::json([
                "status" => false,
                "message" => "Image not found"
            ], 400);
        }

        if ($file["error"] !== UPLOAD_ERR_OK) {
            Response::json([
                "status" => false,
                "message" => "Image upload failed"
            ], 400);
        }

        $maxSize = 5 * 1024 * 1024;
        if ($file["size"] > $maxSize) {
            Response::json([
                "status" => false,
                "message" => "Image size too large (max 5MB)"
            ], 400);
        }

        $allowedMimes = [
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/webp" => "webp"
        ];

        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file["tmp_name"]);

        if (!isset($allowedMimes[$mime])) {
            Response::json([
                "status" => false,
                "message" => "Invalid image type"
            ], 400);
        }

        // Decide environment
        // $env = getenv("APP_ENV") ?: ($_ENV["APP_ENV"] ?? "local");
        $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
        if ($host === "localhost" || $host === "127.0.0.1") {
            $env = "local";
        } else {
            $env = "production";
        }

        if ($env === "local") {
            return self::uploadToLocal($file, $folder, $allowedMimes[$mime]);
        }

        return self::uploadToCloudinary($file, $folder);
    }

    // ======================================================
    // LOCAL STORAGE (for localhost)
    // ======================================================
    private static function uploadToLocal($file, $folder, $extension)
    {
        $basePath = __DIR__ . "/../../public/uploads";
        $targetDir = $basePath . "/" . $folder;

        if (!is_dir($targetDir)) {
            mkdir($targetDir, 0777, true);
        }

        $filename = uniqid("img_", true) . "." . $extension;
        $targetPath = $targetDir . "/" . $filename;

        if (!move_uploaded_file($file["tmp_name"], $targetPath)) {
            Response::json([
                "status" => false,
                "message" => "Failed to save image locally"
            ], 500);
        }

        $publicUrl =
            (isset($_SERVER['HTTPS']) ? 'https' : 'http') .
            '://' .
            $_SERVER['HTTP_HOST'] .
            dirname($_SERVER['SCRIPT_NAME']);

        return [
            "secure_url" => $publicUrl . "/uploads/" . $folder . "/" . $filename,
            "public_id" => $filename,
            "storage" => "local"
        ];
    }

    // ======================================================
    // CLOUDINARY STORAGE (production)
    // ======================================================
    private static function uploadToCloudinary($file, $folder)
    {
        $timestamp = time();

        $cloudName = getenv("CLOUDINARY_CLOUD_NAME") ?: $_ENV["CLOUDINARY_CLOUD_NAME"];
        $apiKey = getenv("CLOUDINARY_API_KEY") ?: $_ENV["CLOUDINARY_API_KEY"];
        $apiSecret = getenv("CLOUDINARY_API_SECRET") ?: $_ENV["CLOUDINARY_API_SECRET"];

        $paramToSign = "folder={$folder}&timestamp={$timestamp}";
        $signature = sha1($paramToSign . $apiSecret);

        $url = "https://api.cloudinary.com/v1_1/{$cloudName}/image/upload";

        $postFields = [
            "file" => new CURLFile($file["tmp_name"]),
            "api_key" => $apiKey,
            "timestamp" => $timestamp,
            "signature" => $signature,
            "folder" => $folder
        ];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => $postFields
        ]);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            Response::json([
                "status" => false,
                "message" => "Cloud upload failed: " . curl_error($ch)
            ], 500);
        }

        curl_close($ch);

        $result = json_decode($response, true);

        if (!isset($result["secure_url"])) {
            Response::json([
                "status" => false,
                "message" => "Cloudinary upload failed"
            ], 500);
        }

        return $result;
    }
}
