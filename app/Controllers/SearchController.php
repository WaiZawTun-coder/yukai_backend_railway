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
use DateTime;

class SearchController
{
    public static function search()
    {
        $conn = Database::connect();
        $authUser = Auth::getUser();
        $user_id = $authUser["user_id"];

        $keyword = trim($_GET["keyword"] ?? "");
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $limit = 5;
        $offset = ($page - 1) * $limit;

        // ✅ Type filtering (all | users | posts)
        $type = strtolower(trim($_GET["type"] ?? "all"));
        if (!in_array($type, ["all", "users", "posts"])) {
            $type = "all";
        }

        if ($keyword === '') {
            Response::json([
                "status" => false,
                "message" => "Keyword is required"
            ]);
            return;
        }

        $search_word = "%{$keyword}%";

        // ✅ Keep response structure unchanged
        $data = [
            "users" => [
                "page" => $page,
                "total_pages" => 0,
                "data" => []
            ],
            "posts" => [
                "page" => $page,
                "total_pages" => 0,
                "data" => []
            ]
        ];

        /* =======================
           SEARCH USERS
        ======================= */

        if ($type === "all" || $type === "users") {

            $sql = "
            SELECT 
    u.user_id,
    u.username,
    u.display_name,
    u.profile_image,
    u.gender,
    
    -- FRIENDSHIP STATUS
    CASE 
        WHEN f.status = 'accepted' THEN 'friends'
        WHEN f.user_1_id = ? AND f.status = 'pending' THEN 'request_sent'
        WHEN f.user_2_id = ? AND f.status = 'pending' THEN 'request_received'
        ELSE 'none'
    END AS friendship_status,

    -- FOLLOWING STATUS
    CASE 
        WHEN fol.follower_user_id = ? THEN 'following'
        ELSE 'not_following'
    END AS following_status

FROM users u

-- LEFT JOIN friend requests
LEFT JOIN friends f ON 
    ( (f.user_1_id = ? AND f.user_2_id = u.user_id) 
      OR (f.user_1_id = u.user_id AND f.user_2_id = ?) )

-- LEFT JOIN following
LEFT JOIN follows fol ON fol.following_user_id = u.user_id AND fol.follower_user_id = ?

WHERE u.display_name LIKE ?               -- search term
  AND u.is_active = 1
  AND u.deactivate = 0
  AND u.user_id != ?                       -- exclude current user
  AND NOT EXISTS (                          -- exclude blocked users
      SELECT 1
      FROM blocks b
      WHERE b.status = 1 AND (
          (b.blocker_user_id = ? AND b.blocked_user_id = u.user_id)
          OR
          (b.blocker_user_id = u.user_id AND b.blocked_user_id = ?)
      )
  )

LIMIT ? OFFSET ?;

        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("iiiiiisiiiii", $user_id, $user_id, $user_id, $user_id, $user_id, $user_id, $search_word, $user_id, $user_id, $user_id, $limit, $offset);
            $stmt->execute();
            $users_result = $stmt->get_result();

            $totalUsers = self::userCountByKeyword($search_word, $user_id);
            $userTotalPages = ceil($totalUsers / $limit);
            $data["users"]["total_pages"] = $userTotalPages;

            while ($user = $users_result->fetch_assoc()) {
                $data["users"]["data"][] = [
                    "user_id" => $user["user_id"],
                    "display_name" => $user["display_name"],
                    "username" => $user["username"],
                    "profile_image" => $user["profile_image"],
                    "gender" => $user["gender"],
                    "friendship_status" => $user["friendship_status"],
                    "following_status" => $user["following_status"]
                ];
            }
        }

        /* =======================
           SEARCH POSTS (PUBLIC) AND Friend Posts
        ======================= */

        if ($type === "all" || $type === "posts") {

            $sql = "
            SELECT 
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

                u.display_name,
                u.gender,
                u.profile_image,

                COUNT(DISTINCT r.post_react_id) AS react_count,
                COUNT(DISTINCT c.post_comment_id) AS comment_count,

                CASE 
                    WHEN COUNT(ur.post_react_id) > 0 THEN 1
                    ELSE 0
                END AS is_liked,

                MAX(ur.reaction) AS reaction

            FROM posts p
            JOIN users u ON u.user_id = p.creator_user_id

            LEFT JOIN post_reacts r ON r.post_id = p.post_id
            LEFT JOIN post_comments c ON c.post_id = p.post_id
            LEFT JOIN post_reacts ur 
                ON ur.post_id = p.post_id 
                AND ur.user_id = ?

            WHERE 
                p.is_deleted = 0
                AND p.is_draft = 0
                AND p.content LIKE ?
                AND NOT EXISTS (
                    SELECT 1
                    FROM blocks b
                    WHERE b.status = 1 AND (
                        (b.blocker_user_id = ? AND b.blocked_user_id = p.creator_user_id)
                        OR
                        (b.blocker_user_id = p.creator_user_id AND b.blocked_user_id = ?)
                    )
                )
                AND (
                    p.privacy = 'public'
                    OR (
                        p.privacy = 'friends'
                        AND EXISTS (
                            SELECT 1
                            FROM friends fr
                            WHERE
                                fr.status = 'accepted'
                                AND (
                                    (fr.user_1_id = ? AND fr.user_2_id = p.creator_user_id)
                                    OR
                                    (fr.user_2_id = ? AND fr.user_1_id = p.creator_user_id)
                                )
                        )
                    )
                )
                 
            GROUP BY p.post_id
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param(
                "isiiiiii",
                $user_id,
                $search_word,
                $user_id,
                $user_id,
                $user_id,
                $user_id,
                $limit,
                $offset
            );
            $stmt->execute();

            $posts_result = $stmt->get_result();
            $posts = [];

            while ($row = $posts_result->fetch_assoc()) {

                $row["creator"] = [
                    "id" => $row["creator_user_id"],
                    "display_name" => $row["display_name"],
                    "gender" => $row["gender"],
                    "profile_image" => $row["profile_image"]
                ];

                unset(
                    $row["display_name"],
                    $row["gender"],
                    $row["profile_image"]
                );

                $row["attachments"] = [];
                $posts[$row["post_id"]] = $row;
            }

            PostController::attachAttachments($conn, $posts);

            $totalPosts = self::postCountByKeywords($search_word, $user_id);
            $totalPostPages = ceil($totalPosts / $limit);
            $data["posts"]["total_pages"] = $totalPostPages;
            $data["posts"]["data"] = array_values($posts);
        }

        /* =======================
           RESPONSE
        ======================= */

        Response::json([
            "status" => true,
            "keyword" => $keyword,
            "data" => $data
        ]);
    }


    private static function postCountByKeywords($search_word, $user_id)
    {
        $conn = Database::connect();

        $sql = "
            SELECT COUNT(*) AS total
            FROM posts p
            WHERE 
                p.is_deleted = 0
                AND p.is_draft = 0
                AND p.content LIKE ?
                AND (
                    p.privacy = 'public'
                    OR (
                        p.privacy = 'friends'
                        AND EXISTS (
                            SELECT 1
                            FROM friends fr
                            WHERE
                                fr.status = 'accepted'
                                AND (
                                    (fr.user_1_id = ? AND fr.user_2_id = p.creator_user_id)
                                    OR
                                    (fr.user_2_id = ? AND fr.user_1_id = p.creator_user_id)
                                )
                        )
                    )
                )
        ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sii", $search_word, $user_id, $user_id);
        $stmt->execute();

        return (int) $stmt->get_result()->fetch_assoc()['total'];
    }

    private static function userCountByKeyword($search_word, $user_id)
    {
        $conn = Database::connect();

        $sql = "
            SELECT COUNT(*) AS total
            FROM users u
            WHERE u.display_name LIKE ?
            AND u.is_active = 1
            AND u.deactivate=0
            AND NOT EXISTS (
                SELECT 1
                FROM blocks b
                WHERE b.status = 1 AND (
                    (b.blocker_user_id = ? AND b.blocked_user_id = u.user_id)
                    OR
                    (b.blocker_user_id = u.user_id AND b.blocked_user_id = ?)
                )
            )
        ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sii", $search_word, $user_id, $user_id);
        $stmt->execute();

        return (int) $stmt->get_result()->fetch_assoc()['total'];
    }


}