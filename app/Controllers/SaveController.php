<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Response;
use App\Core\Request;
use App\Service\ImageService;

class SaveController
{

    public static function savePost()
    {
        $conn = Database::connect();

        $post_id = (int) (Request::input("post_id") ?? 0);
        $saved_list_id = (int) (Request::input("saved_list_id") ?? 0);
        $user_id = (int) (Request::input("user_id") ?? 0);
        $name = trim(Request::input("name") ?? "");

        // post_id is always required
        if ($post_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Post ID is required"
            ]);
            return;
        }

        //create new saved list
        if ($saved_list_id === 0) {

            if ($user_id === 0 || $name === "") {
                Response::json([
                    "status" => false,
                    "message" => "User ID and name are required"
                ]);
                return;
            }

            $sql = "INSERT INTO saved_lists (user_id, name, created_at)
                    VALUES (?, ?, NOW())";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("is", $user_id, $name);
            $stmt->execute();

            $saved_list_id = $conn->insert_id;
            $stmt->close();
        }

        //check duplicate post
        $checkSql = "SELECT 1 FROM saved_posts
                     WHERE saved_list_id = ? AND post_id = ?";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bind_param("ii", $saved_list_id, $post_id);
        $checkStmt->execute();
        $checkStmt->store_result();

        if ($checkStmt->num_rows > 0) {
            Response::json([
                "status" => false,
                "message" => "Post already saved"
            ]);
            return;
        }
        $checkStmt->close();

        //save post
        $sql = "INSERT INTO saved_posts (saved_list_id, post_id, created_at)
                VALUES (?, ?, NOW())";
        $stmtSave = $conn->prepare($sql);
        $stmtSave->bind_param("ii", $saved_list_id, $post_id);
        $stmtSave->execute();
        $stmtSave->close();

        Response::json([
            "status" => true,
            "message" => "Post saved successfully "
        ]);
    }

    //upade saved posts
    public static function updateSavedPosts()
    {
        $conn = Database::connect();
        // $saved_post_id = (int) (Request::input("saved_post_id") ?? 0);
        // $saved_list_id = (int) (Request::input("saved_list_id") ?? 0);
        $saved_post_id = (int) $_GET["post_id"] ?? 0;
        $saved_list_id = (int) $_GET["list_id"] ?? 0;
        //check saved_post_id
        if ($saved_post_id === 0 || $saved_list_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid input"
            ]);
            return;
        }
        //check saved posts existence
        $sql = "select saved_post_id from saved_posts where saved_post_id=?";
        $checkStmt = $conn->prepare($sql);
        $checkStmt->bind_param("i", $saved_post_id);
        $checkStmt->execute();
        $checkStmt->store_result();
        if ($checkStmt->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Saved Posts are not found"

            ]);

        } else {
            $savedUpdate = $conn->prepare("Update saved_posts Set saved_list_id=? where saved_post_id=?");
            $savedUpdate->bind_param("ii", $saved_list_id, $saved_post_id);
            $savedUpdate->execute();
            Response::json([
                "status" => true,
                "message" => "Update Successfully"

            ]);

        }

    }
    //delete saved posts
    public static function deleteSavedPosts()
    {
        $conn = Database::connect();
        $saved_post_id = (int) (Request::input("saved_post_id") ?? 0);
        //check the saved post_id has?
        if ($saved_post_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Saved Post is not found"
            ]);
            ;
            return;
        } else {
            $sql = "Delete From saved_posts where saved_post_id=?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $saved_post_id);
            $stmt->execute();
            Response::json([
                "status" => true,
                "message" => "This saved posts is delected successfully"
            ]);
        }
    }


    //create saved lists
    public static function createSavedLists()
    {
        $conn = Database::connect();
        // $user_id = (int) (Request::input("user_id") ?? 0);
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        $name = trim(Request::input("name") ?? "");
        $sql = "INSERT INTO saved_lists (user_id, name)
                    VALUES (?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("is", $user_id, $name);
        $stmt->execute();
        $saved_list_id = $conn->insert_id;

        $sql = "SELECT * FROM saved_lists where saved_list_id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $saved_list_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $save_list = $result->fetch_assoc();

        Response::json([
            "status" => true,
            "message" => "Save List is created",
            "data" => $save_list
        ]);

    }

    //create saved posts
    public static function createSavedPosts()
    {
        $conn = Database::connect();

        $post_id = (int) (Request::input("post_id") ?? 0);
        $saved_list_id = (int) (Request::input("saved_list_id") ?? 0);

        //post_id is always required
        if ($post_id === 0 || $saved_list_id == 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post or Invalid saved list."
            ]);
            return;
        }

        //check duplicate post
        $checkSql = "SELECT 1 FROM saved_posts
                     WHERE saved_list_id = ? AND post_id = ?";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bind_param("ii", $saved_list_id, $post_id);
        $checkStmt->execute();
        $checkStmt->store_result();

        if ($checkStmt->num_rows > 0) {
            Response::json([
                "status" => false,
                "message" => "Post already saved to this saved list."
            ]);
            return;
        }
        $checkStmt->close();

        $sql = "INSERT INTO saved_posts (saved_list_id, post_id, created_at)
                VALUES (?, ?, NOW())";
        $stmtSave = $conn->prepare($sql);
        $stmtSave->bind_param("ii", $saved_list_id, $post_id);
        $stmtSave->execute();
        $stmtSave->close();

        Response::json([
            "status" => true,
            "message" => "Post saved successfully"
        ]);

    }

    //get Saved Lists
    public static function getSavedLists()
    {
        $conn = Database::connect();

        $username = $_GET["username"];

        if (isset($username)) {
            $user = Auth::getUser();
            $user_id = $user["user_id"];
        } else {
            Response::json([
                "status" => false,
                "message" => "Does not have access for this user."
            ], 400);
            $sql = "SELECT * FROM users WHERE username = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("s", $username);
            $stmt->execute();

            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $user_id = $user["user_id"];
        }

        $sql = "Select * from saved_lists where user_id=?";
        $stmtSave = $conn->prepare($sql);
        $stmtSave->bind_param("i", $user_id);
        $stmtSave->execute();
        $result = $stmtSave->get_result();
        if ($result->num_rows === 0) {
            Response::json([
                "status" => true,
                "message" => "No saved list for " . $user['username']
            ]);
        }
        $savedLists = [];

        while ($row = $result->fetch_assoc()) {
            $savedLists[] = $row;
        }

        Response::json(
            [
                "status" => true,
                "message" => "Saved lists are as follow",
                "data" => $savedLists
            ]

        );
    }

    //get Save Posts
    public static function getSavedPosts($list_id)
    {
        $conn = Database::connect();
        $saved_list_id = (int) $list_id ?? 0;
        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;

        $user = Auth::getUser();
        $user_id = $user["user_id"];

        if ($saved_list_id == 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid List Id"
            ], 404);
        }

        $limit = 5;
        $offset = ($page - 1) * $limit;
        $sql = "SELECT 
                p.post_id,
                p.creator_user_id,
                p.shared_post_id,
                p.privacy,
                p.content,
                p.is_archived,
                p.is_draft,
                p.is_deleted,
                p.is_shared,
                p.created_at,
                p.updated_at,
                u.username,
                u.display_name,
                u.gender,
                u.profile_image,

                COUNT(DISTINCT r.post_react_id) AS react_count,
                COUNT(DISTINCT c.post_comment_id) AS comment_count,
                (COUNT(DISTINCT r.post_react_id) + COUNT(DISTINCT c.post_comment_id)) AS total_engagement,

                CASE 
                    WHEN COUNT(ur.post_react_id) > 0 THEN 1
                    ELSE 0
                END AS is_liked,

                MAX(ur.reaction) AS reaction

            FROM posts p
            JOIN users u ON u.user_id = p.creator_user_id
            LEFT JOIN post_reacts r ON r.post_id = p.post_id
            LEFT JOIN post_comments c ON c.post_id = p.post_id
            LEFT JOIN saved_posts sp ON sp.post_id=p.post_id
            LEFT JOIN saved_lists sl ON sl.saved_list_id=sp.saved_list_id

            LEFT JOIN post_reacts ur 
             ON ur.post_id = p.post_id 
             

            WHERE p.is_deleted = 0
            AND sp.saved_list_id=? AND sl.user_id=?

            GROUP BY p.post_id
            ORDER BY total_engagement DESC, p.created_at DESC
            LIMIT ? OFFSET ?

        ";
        $stmtSave = $conn->prepare($sql);
        $stmtSave->bind_param("iiii", $saved_list_id, $user_id, $limit, $offset);
        $stmtSave->execute();
        $result = $stmtSave->get_result();
        $posts = [];
        while ($row = $result->fetch_assoc()) {
            $row["creator"] = [
                "id" => $row["creator_user_id"],
                "display_name" => $row["display_name"],
                "gender" => $row["gender"],
                "profile_image" => $row["profile_image"],
                "username" => $row["username"]
            ];

            unset(
                $row["display_name"],
                $row["gender"],
                $row["profile_image"],
                $row["username"]
            );

            $row['attachments'] = [];
            $posts[$row['post_id']] = $row;
        }

        PostController::attachAttachments($conn, $posts);

        $totalPosts = self::getSavedPostsCount($list_id);
        $totalPages = ceil($totalPosts / $limit);

        Response::json([
            "status" => true,
            "page" => $page,
            "totalPages" => $totalPages,
            "data" => array_values($posts)
        ]);
    }

    private static function getSavedPostsCount($list_id)
    {
        $conn = Database::connect();

        $sql = "SELECT COUNT(*) AS total FROM saved_posts where saved_list_id=?";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $list_id);
        $stmt->execute();

        $result = $stmt->get_result();

        return (int) $result->fetch_assoc()["total"];
    }

}
