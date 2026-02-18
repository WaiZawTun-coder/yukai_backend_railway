<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Response;
use App\Core\Request;
use App\Service\ImageService;

class PostHidingController
{
    //hide post
    public static function hidePost()
    {
        $conn = Database::connect();

        $user = Auth::getUser();
        $user_id = (int) $user["user_id"];
        $post_id = (int) (Request::input("post_id") ?? 0);

        $sql = "select * from posts where post_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $post_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid Post"
            ]);
            return;
        }

        //insert hide posts
        $sql = "Insert into hide_posts (post_id,user_id) values (?,?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $post_id, $user_id);

        if ($stmt->execute()) {
            Response::json([
                "status" => true,
                "message" => "Hide Successfully"
            ]);
        } else {
            Response::json([
                "status" => false,
                "message" => "Post already hidden"

            ]);
        }
    }
    //unhide post
    public static function unhidePost()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = (int) $user["user_id"];
        $post_id = (int) (Request::input("post_id") ?? 0);

        $sql = "select * from posts where post_id=? and user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $post_id, $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid Post"
            ]);
            return;
        }

        //unhide post
        $sql = "Delete from hide_posts where post_id=? and user_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $post_id, $user_id);

        if ($stmt->execute()) {
            Response::json([
                "status" => true,
                "message" => "Unhide Successfully"
            ]);
        } else {
            Response::json([
                "status" => false,
                "message" => "Post already hidden"
            ]);
        }
    }
}
