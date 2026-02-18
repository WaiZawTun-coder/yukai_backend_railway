<?php
namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Response;
use App\Core\Request;
use App\Service\ImageService;
use Exception;

class PostController
{
    /* =====================================================
     * Helper: Attach post_attachments to posts
     * ===================================================== */
    public static function attachAttachments($conn, &$posts)
    {
        if (empty($posts))
            return;

        $postIds = array_keys($posts);
        $placeholders = implode(",", array_fill(0, count($postIds), "?"));
        $types = str_repeat("i", count($postIds));

        $sql = "
            SELECT post_attachment_id, post_id, file_path, type
            FROM post_attachments
            WHERE post_id IN ($placeholders)
        ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$postIds);
        $stmt->execute();
        $result = $stmt->get_result();

        while ($row = $result->fetch_assoc()) {
            $posts[$row['post_id']]['attachments'][] = $row;
        }
    }

    private static function attachTaggedUsers($conn, &$posts)
    {
        if (empty($posts))
            return;

        $postIds = array_keys($posts);
        $placeholders = implode(',', array_fill(0, count($postIds), '?'));
        $types = str_repeat('i', count($postIds));

        $sql = "
        SELECT 
            pt.post_id,
            u.user_id,
            u.username,
            u.display_name,
            u.profile_image
        FROM post_tags pt
        JOIN users u ON u.user_id = pt.tagged_user_id
        WHERE pt.post_id IN ($placeholders)
    ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$postIds);
        $stmt->execute();
        $result = $stmt->get_result();

        while ($row = $result->fetch_assoc()) {
            $posts[$row["post_id"]]["tagged_users"][] = [
                "user_id" => $row["user_id"],
                "username" => $row["username"],
                "display_name" => $row["display_name"],
                "profile_image" => $row["profile_image"]
            ];
        }
    }


    /* =====================================================
     * Get all posts
     * ===================================================== */


    public static function getPosts()
    {
        $conn = Database::connect();

        /* -------------------- Resolve User -------------------- */

        $authUser = Auth::getUser();
        $user_id = (int) (Request::input("user_id") ?? ($authUser["user_id"] ?? 0));

        if ($user_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Unauthorized"
            ], 401);
        }

        /* -------------------- Pagination -------------------- */

        $page = max(1, (int) ($_GET["page"] ?? 1));
        $limit = 5;
        $offset = ($page - 1) * $limit;

        /* -------------------- SQL -------------------- */

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

    u.display_name,
    u.username,
    u.gender,
    u.profile_image,

    COUNT(DISTINCT r.post_react_id) AS react_count,
    COUNT(DISTINCT c.post_comment_id) AS comment_count,

    (COUNT(DISTINCT r.post_react_id) + COUNT(DISTINCT c.post_comment_id)) AS total_engagement,

    -- Weighted engagement
    (
        COUNT(DISTINCT r.post_react_id) * 1 +
        COUNT(DISTINCT c.post_comment_id) * 3
    ) AS weighted_engagement,

    -- Feed ranking score (engagement + time decay)
    (
        (
            COUNT(DISTINCT r.post_react_id) * 1 +
            COUNT(DISTINCT c.post_comment_id) * 3
        ) 
        /
        POW(TIMESTAMPDIFF(HOUR, p.created_at, NOW()) + 2, 1.4)
    ) AS feed_score,

    CASE 
        WHEN COUNT(ur.post_react_id) > 0 THEN 1
        ELSE 0
    END AS is_liked,

    MAX(ur.reaction) AS reaction

FROM posts p
JOIN users u 
    ON u.user_id = p.creator_user_id

LEFT JOIN post_reacts r 
    ON r.post_id = p.post_id

LEFT JOIN post_comments c 
    ON c.post_id = p.post_id

LEFT JOIN post_reacts ur 
    ON ur.post_id = p.post_id
   AND ur.user_id = ?

LEFT JOIN hide_posts hp
    ON hp.post_id = p.post_id
   AND hp.user_id = ?

WHERE p.is_deleted = 0
  AND p.is_archived = 0
  AND p.is_draft = 0
  AND p.is_banned = 0
  AND u.is_active = 1
  AND hp.post_id IS NULL

  AND (
        p.privacy = 'public'

     OR (p.privacy = 'friends' AND EXISTS (
            SELECT 1 
            FROM friends f
            WHERE f.status = 'accepted'
              AND (
                    (f.user_1_id = p.creator_user_id AND f.user_2_id = ?)
                 OR (f.user_2_id = p.creator_user_id AND f.user_1_id = ?)
              )
     ))

     OR (p.privacy = 'private' AND p.creator_user_id = ?)
  )

GROUP BY p.post_id

ORDER BY feed_score DESC, p.created_at DESC
LIMIT ? OFFSET ?;

    ";


        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            Response::json([
                "status" => false,
                "message" => "Database error: " . $conn->error
            ], 500);
        }

        $stmt->bind_param("iiiiiii", $user_id, $user_id, $user_id, $user_id, $user_id, $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();

        /* -------------------- Hydrate Posts -------------------- */

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

            $row["attachments"] = [];
            $row["tagged_users"] = [];
            $posts[$row["post_id"]] = $row;
        }

        self::attachAttachments($conn, $posts);
        self::attachTaggedUsers($conn, $posts);

        /* -------------------- Pagination Meta -------------------- */

        $totalPosts = self::getPostCount();
        $totalPages = max(1, ceil($totalPosts / $limit));

        Response::json([
            "status" => true,
            "page" => $page,
            "totalPages" => $totalPages,
            "data" => array_values($posts)
        ]);
    }


    /* =====================================================
     * Get posts by user ID
     * ===================================================== */
    public static function getPostsByUsername($username = "")
    {
        $conn = Database::connect();
        $user = Auth::getUser();

        if (!$username) {
            Response::json([
                "status" => false,
                "message" => "Username is required."
            ], 404);
        }

        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
        $limit = 5;
        $offset = ($page - 1) * $limit;

        $user_id = (int) ($user["user_id"] ?? 0);

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

    cu.display_name,
    cu.gender,
    cu.profile_image,
    cu.username,

    IFNULL(r.react_count, 0) AS react_count,
    IFNULL(c.comment_count, 0) AS comment_count,

    IF(ur.post_react_id IS NOT NULL, 1, 0) AS is_liked,
    ur.reaction

FROM posts p
JOIN users cu 
    ON cu.user_id = p.creator_user_id

LEFT JOIN (
    SELECT post_id, COUNT(*) AS react_count
    FROM post_reacts
    GROUP BY post_id
) r ON r.post_id = p.post_id

LEFT JOIN (
    SELECT post_id, COUNT(*) AS comment_count
    FROM post_comments
    GROUP BY post_id
) c ON c.post_id = p.post_id

LEFT JOIN post_reacts ur
    ON ur.post_id = p.post_id
   AND ur.user_id = ?

LEFT JOIN hide_posts hp
    ON hp.post_id = p.post_id
   AND hp.user_id = ?

WHERE p.is_deleted = 0
  AND p.is_archived = 0
  AND p.is_draft = 0
  AND p.is_banned = 0
  AND cu.username = ?
  AND hp.post_id IS NULL
  AND (
        p.privacy = 'public'
        OR (
            p.privacy = 'friends'
            AND EXISTS (
                SELECT 1
                FROM friends f
                WHERE f.status = 'accepted'
                  AND (
                        (f.user_1_id = p.creator_user_id AND f.user_2_id = ?)
                     OR (f.user_2_id = p.creator_user_id AND f.user_1_id = ?)
                  )
            )
        )
        OR (p.privacy = 'private' AND p.creator_user_id = ?)
        OR (p.creator_user_id = ?)
  )

ORDER BY p.created_at DESC
LIMIT ? OFFSET ?;


    ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iisiiiiii", $user_id, $user_id, $username, $user_id, $user_id, $user_id, $user_id, $limit, $offset);
        $stmt->execute();

        $result = $stmt->get_result();

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

            $row["attachments"] = [];
            $row["tagged_users"] = [];
            $posts[$row["post_id"]] = $row;
        }

        self::attachAttachments($conn, $posts);
        self::attachTaggedUsers($conn, $posts);

        $totalPosts = self::getPostCountByUsername($username);
        $totalPages = ceil($totalPosts / $limit);

        Response::json([
            "status" => true,
            "page" => $page,
            "totalPages" => $totalPages,
            "data" => array_values($posts)
        ]);

    }


    /* =====================================================
     * Get posts from following users
     * ===================================================== */
    public static function getFollowingPosts()
    {
        $conn = Database::connect();
        $input = Request::json();

        // Get authenticated user
        $user = Auth::getUser();
        $user_id = $user["user_id"] ?? 0;

        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "User not authenticated"
            ], 401);
        }

        // Pagination
        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
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

            u.display_name,
            u.username,
            u.gender,
            u.profile_image,

            COUNT(DISTINCT r.post_react_id) AS react_count,
            COUNT(DISTINCT c.post_comment_id) AS comment_count,
            (COUNT(DISTINCT r.post_react_id) + COUNT(DISTINCT c.post_comment_id)) AS total_engagement,

            -- Weighted engagement
            (
                COUNT(DISTINCT r.post_react_id) * 1 +
                COUNT(DISTINCT c.post_comment_id) * 3
            ) AS weighted_engagement,
            
            -- Feed ranking score (engagement + time decay)
            (
                (
                    COUNT(DISTINCT r.post_react_id) * 1 +
                    COUNT(DISTINCT c.post_comment_id) * 3
                ) 
                /
                POW(TIMESTAMPDIFF(HOUR, p.created_at, NOW()) + 2, 1.4)
            ) AS feed_score,

            CASE 
                WHEN COUNT(ur.post_react_id) > 0 THEN 1
                ELSE 0
            END AS is_liked,

            MAX(ur.reaction) AS reaction

        FROM posts p

        JOIN users u ON u.user_id = p.creator_user_id

        -- Only posts from users the current user is following
        INNER JOIN follows f 
            ON f.following_user_id = p.creator_user_id 
           AND f.follower_user_id = ?

        -- Post reactions and comments
        LEFT JOIN post_reacts r ON r.post_id = p.post_id
        LEFT JOIN post_comments c ON c.post_id = p.post_id

        -- Current user's reaction
        LEFT JOIN post_reacts ur 
            ON ur.post_id = p.post_id
           AND ur.user_id = ?

        -- Filter out hidden posts
        LEFT JOIN hide_posts hp
            ON hp.post_id = p.post_id
           AND hp.user_id = ?

        WHERE p.is_deleted = 0
          AND p.is_archived = 0
          AND p.is_draft = 0
          AND p.is_banned = 0
  AND u.is_active = 1
          AND hp.post_id IS NULL

          AND (
            p.privacy = 'public'
            OR (p.privacy = 'friends' AND EXISTS (
                SELECT 1
                FROM friends f
                WHERE f.status = 'accepted'
                    AND (
                        (f.user_1_id = p.creator_user_id AND f.user_2_id = ?)
                        OR (f.user_2_id = p.creator_user_id AND f.user_1_id = ?)
                    )
            ))

            OR (p.privacy = 'private' AND p.creator_user_id = ?)
          )

        GROUP BY p.post_id
        ORDER BY total_engagement DESC, p.created_at DESC
        LIMIT ? OFFSET ?
    ";

        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            Response::json([
                "status" => false,
                "message" => "Database error: " . $conn->error
            ], 500);
        }

        $stmt->bind_param("iiiiiiii", $user_id, $user_id, $user_id, $user_id, $user_id, $user_id, $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();

        $posts = [];
        while ($row = $result->fetch_assoc()) {
            $creator = [
                "id" => $row["creator_user_id"] ?? null,
                "display_name" => $row["display_name"] ?? null,
                "gender" => $row["gender"] ?? null,
                "profile_image" => $row["profile_image"] ?? null,
                "username" => $row["username"] ?? null
            ];

            unset(
                $row["display_name"],
                $row["gender"],
                $row["profile_image"],
                $row["username"]
            );

            $row["creator"] = $creator;
            $row["attachments"] = [];
            $row["tagged_users"] = [];

            $posts[$row["post_id"]] = $row;
        }

        // Attach post attachments
        self::attachAttachments($conn, $posts);
        self::attachTaggedUsers($conn, $posts);

        // Total posts (exclude hidden posts)
        $totalPosts = self::getFollowingPostCount($user_id);
        $totalPages = ceil($totalPosts / $limit);

        Response::json([
            "status" => true,
            "page" => $page,
            "totalPages" => $totalPages,
            "data" => array_values($posts)
        ]);
    }


    /* =====================================================
     * Get posts by post ID
     * ===================================================== */
    public static function getPostsByPostId()
    {
        $conn = Database::connect();
        // $post_id = (int) ($post_id ?? 0);
        $post_id = (int) ($_GET["post_id"] ?? 0);


        if ($post_id == 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post_id"
            ], 404);
        }

        $user = Auth::getUser();
        $user_id = $user["user_id"] ?? 0;

        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "User not authenticated"
            ], 401);
            return;
        }

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

    u.display_name,
    u.gender,
    u.profile_image,
    u.username,

    (
        SELECT COUNT(*) 
        FROM post_reacts pr 
        WHERE pr.post_id = p.post_id
    ) AS react_count,

    (
        SELECT COUNT(*) 
        FROM post_comments pc 
        WHERE pc.post_id = p.post_id
    ) AS comment_count,

    CASE 
        WHEN ur.post_react_id IS NOT NULL THEN 1
        ELSE 0
    END AS is_liked,

    ur.reaction

FROM posts p
JOIN users u 
    ON u.user_id = p.creator_user_id

LEFT JOIN post_reacts ur 
    ON ur.post_id = p.post_id
   AND ur.user_id = ?

LEFT JOIN hide_posts hp
    ON hp.post_id = p.post_id
   AND hp.user_id = ?

WHERE 
    p.post_id = ?
    AND p.is_deleted = 0
    AND p.is_archived = 0
    AND p.is_draft = 0
    AND p.is_banned = 0
  AND u.is_active = 1
    AND hp.post_id IS NULL
    AND (
        p.privacy = 'public'
        OR (p.privacy = 'friends' AND EXISTS (
            SELECT 1 FROM friends f
            WHERE f.status = 'accepted'
              AND (
                    (f.user_1_id = p.creator_user_id AND f.user_2_id = ?)
                 OR (f.user_2_id = p.creator_user_id AND f.user_1_id = ?)
              )
        ))
        OR (p.privacy = 'private' AND p.creator_user_id = ?)
        OR p.creator_user_id = ?
    );

        ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iiiiiii", $user_id, $user_id, $post_id, $user_id, $user_id, $user_id, $user_id);
        $stmt->execute();

        $result = $stmt->get_result();
        $post = $result->fetch_assoc();

        if (!$post) {
            Response::json([
                "status" => false,
                "message" => "Post not found or access denied"
            ], 404);
            return;
        }

        $post["creator"] = [
            "id" => $post["creator_user_id"],
            "display_name" => $post["display_name"],
            "gender" => $post["gender"],
            "profile_image" => $post["profile_image"]
        ];

        unset(
            $post["display_name"],
            $post["gender"],
            $post["profile_image"],
            $post["username"]
        );
        $posts = [
            $post["post_id"] => $post
        ];

        self::attachAttachments($conn, $posts);
        self::attachTaggedUsers($conn, $posts);

        Response::json([
            "status" => true,
            "data" => array_values($posts)
        ]);
    }

    public static function getDraftedPost()
    {
        $conn = Database::connect();

        $user = Auth::getUser();
        $user_id = $user["user_id"] ?? 0;

        if ($user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "User not authenticated"
            ], 401);
            return;
        }

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

    u.display_name,
    u.gender,
    u.profile_image,
    u.username,

    (
        SELECT COUNT(*) 
        FROM post_reacts pr 
        WHERE pr.post_id = p.post_id
    ) AS react_count,

    (
        SELECT COUNT(*) 
        FROM post_comments pc 
        WHERE pc.post_id = p.post_id
    ) AS comment_count,

    CASE 
        WHEN ur.post_react_id IS NOT NULL THEN 1
        ELSE 0
    END AS is_liked,

    ur.reaction

FROM posts p
JOIN users u 
    ON u.user_id = p.creator_user_id

LEFT JOIN post_reacts ur 
    ON ur.post_id = p.post_id
   AND ur.user_id = ?

WHERE 
    p.creator_user_id = ?
    AND p.is_deleted = 0
    AND p.is_archived = 0
    AND p.is_draft = 1
ORDER BY p.updated_at DESC LIMIT 1;

        ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $user_id, $user_id);
        $stmt->execute();

        $result = $stmt->get_result();
        $post = $result->fetch_assoc();

        if (!$post) {
            Response::json([
                "status" => false,
                "message" => "Post not found or access denied"
            ], 404);
            return;
        }

        $post["creator"] = [
            "id" => $post["creator_user_id"],
            "display_name" => $post["display_name"],
            "gender" => $post["gender"],
            "profile_image" => $post["profile_image"]
        ];

        unset(
            $post["display_name"],
            $post["gender"],
            $post["profile_image"],
            $post["username"]
        );
        $posts = [
            $post["post_id"] => $post
        ];

        self::attachAttachments($conn, $posts);
        self::attachTaggedUsers($conn, $posts);

        Response::json([
            "status" => true,
            "data" => array_values($posts)
        ]);
    }



    /* =====================================================
     * Create Post
     * ===================================================== */
    public static function createPost()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $creator_id = $user["user_id"];

        if (!$creator_id) {
            Response::json([
                "status" => false,
                "message" => "Unauthentication"
            ]);
            return;
        }

        $content = trim(Request::input("content") ?? '');
        $privacy = Request::input("privacy") ?? 'public';
        $shared_post_id = Request::input("shared_post_id") ?? null;
        $is_draft = (int) (Request::input("is_draft") ?? 0);
        $is_archived = (int) (Request::input("is_archived") ?? 0);

        $post_id = (int) (Request::input("post_id") ?? 0);

        $tag_friends = Request::input("tag_friends") ?? [];

        if (!is_array($tag_friends)) {
            $tag_friends = [$tag_friends];
        }

        $tag_friends = array_map('intval', $tag_friends);

        if ($creator_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid creator"
            ], 400);
        }
        // $userSql="SELECT user_id,is_active from users where user_id=?";
        // $user   =$conn->prepare($userSql);
        // $user   ->bind_param("i",$creator_id);
        // $user   ->execute();
        // $userResult=$user->get_result()->fetch_assoc();
        // if((int)$userResult['is_active']===0){
        //     Response::json([
        //         "status"=>false,
        //         "message"=>"you cannot create post(Inactive user)"
        //     ]);
        // }

        // Start transaction
        $conn->begin_transaction();

        try {
            // =============================
            // Insert post
            // =============================
            if ($post_id !== 0) {
                $sql = "UPDATE posts SET content = ?, privacy = ?, is_draft = ? WHERE post_id = ?";

                $stmt = $conn->prepare($sql);
                $stmt->bind_param(
                    "ssii",
                    $content,
                    $privacy,
                    $is_draft,
                    $post_id
                );

                $deleteSql = "DELETE FROM post_tags WHERE post_id = ?";
                $deleteStmt = $conn->prepare($deleteSql);
                $deleteStmt->bind_param("i", $post_id);
                $deleteStmt->execute();
            } else {
                $sql = "INSERT INTO posts 
                    (creator_user_id, content, privacy, shared_post_id, is_draft, is_archived, is_deleted, is_shared, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0, ?, NOW())";

                $is_shared = $shared_post_id ? 1 : 0;

                $stmt = $conn->prepare($sql);
                $stmt->bind_param(
                    "issiiii",
                    $creator_id,
                    $content,
                    $privacy,
                    $shared_post_id,
                    $is_draft,
                    $is_archived,
                    $is_shared
                );
            }

            $stmt->execute();

            if ($post_id == 0)
                $post_id = $conn->insert_id;

            // =============================
            // Handle post_attachments (optional)
            // =============================
            if (!empty($_FILES['attachments'])) {
                foreach ($_FILES['attachments']['tmp_name'] as $index => $tmpPath) {
                    if (!is_uploaded_file($tmpPath))
                        continue;

                    $fileArray = [
                        "tmp_name" => $_FILES['attachments']['tmp_name'][$index],
                        "name" => $_FILES['attachments']['name'][$index],
                        "type" => $_FILES['attachments']['type'][$index],
                        "error" => $_FILES['attachments']['error'][$index],
                        "size" => $_FILES['attachments']['size'][$index],
                    ];

                    // Upload using ImageService
                    $uploadResult = ImageService::uploadImage($fileArray, "posts-images");

                    // Store in DB
                    $attachSql = "
                        INSERT INTO post_attachments (post_id, file_path, type)
                        VALUES (?, ?, ?)
                    ";
                    $stmtAttach = $conn->prepare($attachSql);
                    $fileUrl = $uploadResult["secure_url"];
                    // $mime = mime_content_type($fileArray['tmp_name']) ?? "application/octet-stream";
                    $fileType = explode("/", $fileArray['type'])[0];

                    $stmtAttach->bind_param(
                        "iss",
                        $post_id,
                        $fileUrl,
                        $fileType
                    );
                    $stmtAttach->execute();
                }
            }

            if (!empty($tag_friends)) {

                $insertSql = "INSERT INTO post_tags (post_id, tagged_user_id) VALUES (?, ?)";
                $insertStmt = $conn->prepare($insertSql);

                foreach ($tag_friends as $user_id) {
                    if ($user_id <= 0)
                        continue;

                    $insertStmt->bind_param("ii", $post_id, $user_id);
                    $insertStmt->execute();
                }
            }


            // Commit transaction
            $conn->commit();

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

                        u.display_name,
                        u.gender,
                        u.profile_image,
                        u.username,

                        COUNT(DISTINCT r.post_react_id) AS react_count,
                        COUNT(DISTINCT c.post_comment_id) AS comment_count,

                        CASE 
                            WHEN COUNT(ur.post_react_id) > 0 THEN 1
                            ELSE 0
                        END AS is_liked,

                        MAX(ur.reaction) AS reaction

                    FROM posts p
                    JOIN users u 
                        ON u.user_id = p.creator_user_id

                    LEFT JOIN post_reacts r 
                        ON r.post_id = p.post_id

                    LEFT JOIN post_comments c 
                        ON c.post_id = p.post_id

                    LEFT JOIN post_reacts ur 
                        ON ur.post_id = p.post_id
                       AND ur.user_id = ?

                    WHERE 
                        p.post_id = ?
                        AND p.is_deleted = 0
                        AND (
                            p.privacy = ?
                            OR p.creator_user_id = ?
                        )

                    GROUP BY p.post_id";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("iisi", $user_id, $post_id, $privacy, $user_id);
            $stmt->execute();

            $result = $stmt->get_result();
            $post = $result->fetch_assoc();

            if (!$post) {
                Response::json([
                    "status" => false,
                    "message" => "Post not found or access denied"
                ], 404);
                return;
            }

            $post["creator"] = [
                "id" => $post["creator_user_id"],
                "display_name" => $post["display_name"],
                "gender" => $post["gender"],
                "profile_image" => $post["profile_image"]
            ];

            unset(
                $post["display_name"],
                $post["gender"],
                $post["profile_image"],
                $post["username"]
            );
            $posts = [
                $post["post_id"] => $post
            ];

            self::attachAttachments($conn, $posts);
            self::attachTaggedUsers($conn, $posts);

            Response::json([
                "status" => true,
                "message" => "Post created successfully",
                "post_id" => $post_id,
                "data" => array_values($posts)
            ]);

        } catch (\Throwable $e) {

            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => "Failed to create post",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    private static function getUserDefaultPrivacy($userId)
    {
        $conn = Database::connect();

        // Make sure we're using the yukai database
        $conn->select_db("yukai");

        $sql = "SELECT default_privacy FROM user_privacy_settings WHERE user_id = ?";
        $stmt = $conn->prepare($sql);

        if (!$stmt) {
            error_log("SQL Error: " . $conn->error);
            return 'public'; // Fallback
        }

        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            return $row['default_privacy'];
        }

        return 'public'; // Default value
    }
    /* =====================================================
     * Edit Post
     * ===================================================== */
    public static function editPost()
    {
        $conn = Database::connect();
        $creator_id = (int) (Request::input("creator_id") ?? 0);
        $post_id = (int) (Request::input("post_id") ?? 0);



        $privacy = trim(Request::input("privacy") ?? 'public');
        $is_deleted = (int) (Request::input("is_deleted") ?? 0);
        $who_can_comment = trim(Request::input("who_can_comment") ?? "");
        $who_can_react = trim(Request::input("who_can_react") ?? "");
        $who_can_share = trim(Request::input("who_can_share") ?? "");
        $content = trim(Request::input("content") ?? "");
        $shared_post_id = (int) (Request::input("shared_post_id") ?? 0);

        if ($post_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post"
            ], 400);
        }
        $fields = [];
        $params = [];
        $types = "";



        if ($privacy) {
            $fields[] = "privacy = ?";
            $params[] = $privacy;
            $types .= "s";
        }

        if ($is_deleted !== null) {
            $fields[] = "is_deleted = ?";
            $params[] = (int) $is_deleted;
            $types .= "i";
        }

        if ($who_can_comment) {
            $fields[] = "who_can_comment = ?";
            $params[] = $who_can_comment;
            $types .= "s";
        }

        if ($who_can_react) {
            $fields[] = "who_can_react = ?";
            $params[] = $who_can_react;
            $types .= "s";
        }

        if ($who_can_share) {
            $fields[] = "who_can_share = ?";
            $params[] = $who_can_share;
            $types .= "s";
        }

        if ($content) {
            $fields[] = "content = ?";
            $params[] = $content;
            $types .= "s";
        }

        if ($shared_post_id) {
            $fields[] = "shared_post_id = ?";
            $params[] = $shared_post_id;
            $types .= "s";
        }

        if (empty($fields)) {
            Response::json([
                "status" => false,
                "message" => "Nothing to update"
            ], 400);
        }

        $fields[] = "updated_at = NOW()";

        $sql = "
            UPDATE posts
            SET " . implode(", ", $fields) . "
            WHERE post_id = ? AND creator_user_id = ?
        ";

        $params[] = $post_id;
        $params[] = $creator_id;
        $types .= "ii";
        // Start transaction
        $conn->begin_transaction();

        try {
            // Update post
            $stmt = $conn->prepare($sql);
            $stmt->bind_param($types, ...$params);
            $stmt->execute();



            // =============================
            // Handle post_attachments (optional)
            // =============================
            if (!empty($_FILES['attachments'])) {
                foreach ($_FILES['attachments']['tmp_name'] as $index => $tmpPath) {
                    if (!is_uploaded_file($tmpPath))
                        continue;

                    $fileArray = [
                        "tmp_name" => $_FILES['attachments']['tmp_name'][$index],
                        "name" => $_FILES['attachments']['name'][$index],
                        "type" => $_FILES['attachments']['type'][$index],
                        "error" => $_FILES['attachments']['error'][$index],
                        "size" => $_FILES['attachments']['size'][$index],
                    ];

                    // Upload using ImageService
                    $uploadResult = ImageService::uploadImage($fileArray, "posts-images");

                    // Store in DB
                    $attachSql = "
                        INSERT INTO post_attachments (post_id, file_path, type)
                        VALUES (?, ?, ?)
                    ";
                    $stmtAttach = $conn->prepare($attachSql);
                    $fileUrl = $uploadResult["secure_url"];
                    // $mime = mime_content_type($fileArray['tmp_name']) ?? "application/octet-stream";
                    $fileType = explode("/", $fileArray['type'])[0];

                    $stmtAttach->bind_param(
                        "iss",
                        $post_id,
                        $fileUrl,
                        $fileType
                    );
                    $stmtAttach->execute();
                }
            }


            // Commit transaction
            $conn->commit();
            $user_id = $creator_id;

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
JOIN users u 
    ON u.user_id = p.creator_user_id

LEFT JOIN post_reacts r 
    ON r.post_id = p.post_id

LEFT JOIN post_comments c 
    ON c.post_id = p.post_id

LEFT JOIN post_reacts ur 
    ON ur.post_id = p.post_id
   AND ur.user_id = ?

WHERE 
    p.post_id = ?
    AND p.is_deleted = 0
    AND (
        p.privacy = 'public'
        OR p.creator_user_id = ?
    )

GROUP BY p.post_id
    ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("iii", $user_id, $post_id, $user_id);
            $stmt->execute();

            $result = $stmt->get_result();
            $post = $result->fetch_assoc();

            if (!$post) {
                Response::json([
                    "status" => false,
                    "message" => "Post not found or access denied"
                ], 404);
                return;
            }

            $post["creator"] = [
                "id" => $post["creator_user_id"],
                "display_name" => $post["display_name"],
                "gender" => $post["gender"],
                "profile_image" => $post["profile_image"]
            ];

            unset(
                $post["display_name"],
                $post["gender"],
                $post["profile_image"]
            );
            $posts = [
                $post["post_id"] => $post
            ];

            self::attachAttachments($conn, $posts);

            Response::json([
                "status" => true,
                "message" => "Post Edit successfully",
                "post_id" => $post_id,
                "data" => array_values($posts)
            ]);

        } catch (\Throwable $e) {

            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => "Failed to edit post",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    /* =====================================================
     * Edit Post by Privacy
     * ===================================================== */
    public static function editPostPrivacy()
    {
        $conn = Database::connect();
        $creator_id = (int) (Request::input("creator_id") ?? 0);
        $post_id = (int) (Request::input("post_id") ?? 0);
        $privacy = trim(Request::input("privacy") ?? 'public');


        if ($post_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post"
            ], 400);
        }

        // Start transaction
        $conn->begin_transaction();

        try {
            // =============================
            // Insert post
            // =============================
            $sql = "
                    UPDATE posts
                    SET privacy = ?,updated_at = NOW()
                    WHERE post_id = ? and creator_user_id=?
        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param(
                "sii",

                $privacy,
                $post_id,
                $creator_id
            );

            $stmt->execute();



            // =============================
            // Handle post_attachments (optional)
            // =============================
            if (!empty($_FILES['attachments'])) {
                foreach ($_FILES['attachments']['tmp_name'] as $index => $tmpPath) {
                    if (!is_uploaded_file($tmpPath))
                        continue;

                    $fileArray = [
                        "tmp_name" => $_FILES['attachments']['tmp_name'][$index],
                        "name" => $_FILES['attachments']['name'][$index],
                        "type" => $_FILES['attachments']['type'][$index],
                        "error" => $_FILES['attachments']['error'][$index],
                        "size" => $_FILES['attachments']['size'][$index],
                    ];

                    // Upload using ImageService
                    $uploadResult = ImageService::uploadImage($fileArray, "posts-images");

                    // Store in DB
                    $attachSql = "
                        INSERT INTO post_attachments (post_id, file_path, type)
                        VALUES (?, ?, ?)
                    ";
                    $stmtAttach = $conn->prepare($attachSql);
                    $fileUrl = $uploadResult["secure_url"];
                    // $mime = mime_content_type($fileArray['tmp_name']) ?? "application/octet-stream";
                    $fileType = explode("/", $fileArray['type'])[0];

                    $stmtAttach->bind_param(
                        "iss",
                        $post_id,
                        $fileUrl,
                        $fileType
                    );
                    $stmtAttach->execute();
                }
            }


            // Commit transaction
            $conn->commit();
            $user_id = $creator_id;

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
JOIN users u 
    ON u.user_id = p.creator_user_id

LEFT JOIN post_reacts r 
    ON r.post_id = p.post_id

LEFT JOIN post_comments c 
    ON c.post_id = p.post_id

LEFT JOIN post_reacts ur 
    ON ur.post_id = p.post_id
   AND ur.user_id = ?

WHERE 
    p.post_id = ?
    AND p.is_deleted = 0
    AND (
        p.privacy = 'public'
        OR p.creator_user_id = ?
    )

GROUP BY p.post_id
    ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("iii", $user_id, $post_id, $user_id);
            $stmt->execute();

            $result = $stmt->get_result();
            $post = $result->fetch_assoc();

            if (!$post) {
                Response::json([
                    "status" => false,
                    "message" => "Post not found or access denied"
                ], 404);
                return;
            }

            $post["creator"] = [
                "id" => $post["creator_user_id"],
                "display_name" => $post["display_name"],
                "gender" => $post["gender"],
                "profile_image" => $post["profile_image"]
            ];

            unset(
                $post["display_name"],
                $post["gender"],
                $post["profile_image"]
            );
            $posts = [
                $post["post_id"] => $post
            ];

            self::attachAttachments($conn, $posts);

            Response::json([
                "status" => true,
                "message" => "Post Edit successfully",
                "post_id" => $post_id,
                "data" => array_values($posts)
            ]);

        } catch (\Throwable $e) {

            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => "Failed to edit post",
                "error" => $e->getMessage()
            ], 500);
        }
    }
    /* =====================================================
     *  Edit Post Content History
     * ===================================================== */

    public static function editHistory()
    {
        $conn = Database::connect();

        // FIX 1: use Request::input instead of $input
        $post_id = (int) (Request::input("post_id") ?? 0);
        $creator_id = (int) (Request::input("creator_id") ?? 0);

        $content = trim(Request::input("content") ?? "");

        if ($post_id === 0 || $creator_id === 0 || $content === '') {
            Response::json([
                "status" => false,
                "message" => "Invalid input"
            ], 400);
            return; // FIX 2
        }

        $conn->begin_transaction();

        try {

            $sql = "
                SELECT content
                FROM posts
                WHERE post_id = ? AND creator_user_id = ?
                FOR UPDATE
            ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ii", $post_id, $creator_id);
            $stmt->execute();

            $oldPost = $stmt->get_result()->fetch_assoc();

            // FIX 3: define variables
            $oldContent = $oldPost['content'];


            // change edit history


            $historySql = "
                    INSERT INTO edit_history (
                        post_id,
                        old_content
                    ) VALUES (?, ?)
                ";

            $stmtHistory = $conn->prepare($historySql);
            $stmtHistory->bind_param(
                "is",
                $post_id,
                $oldContent,

            );
            $stmtHistory->execute();


            // update post content
            $updateSql = "
                UPDATE posts
                SET content = ?, updated_at = NOW()
                WHERE post_id = ? AND creator_user_id = ?
            ";

            $stmtUpdate = $conn->prepare($updateSql);
            $stmtUpdate->bind_param(
                "sii",
                $content,
                $post_id,
                $creator_id
            );
            $stmtUpdate->execute();

            $conn->commit();

            Response::json([
                "status" => true,
                "message" => "Post edited successfully"
            ]);

        } catch (\Throwable $e) {

            $conn->rollback();

            Response::json([
                "status" => false,
                "message" => "Failed to edit post",
                "error" => $e->getMessage()
            ], 500);
        }
    }
    /* =====================================================
     *  Get All Edit History
     * ===================================================== */
    public static function getEditHistory()
    {
        $conn = Database::connect();


        $post_id = (int) (Request::input("post_id") ?? 0);

        if ($post_id === 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post_id"
            ], 400);
            return;
        }

        try {

            $sql = "SELECT history_id, old_value, new_value, edited_at 
                    FROM edit_history 
                    WHERE post_id = ? 
                    ORDER BY edited_at DESC";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $post_id);
            $stmt->execute();

            $result = $stmt->get_result();
            $history = [];

            while ($row = $result->fetch_assoc()) {
                $history[] = [
                    "history_id" => $row["history_id"],
                    "old_value" => $row["old_value"],
                    "new_value" => $row["new_value"],
                    "edited_at" => $row["edited_at"]
                ];
            }
            Response::json([
                "status" => true,
                "post_id" => $post_id,
                "data" => $history
            ]);

        } catch (\Throwable $e) {
            Response::json([
                "status" => false,
                "message" => "Failed to get edit history",
                "error" => $e->getMessage()
            ], 500);
        }
    }

    /* =====================================================
     *  Insert React
     * ===================================================== */
    public static function reactPost()
    {
        $conn = Database::connect();
        $input = Request::json();

        $user_id = (int) ($input["user_id"] ?? 0);
        $post_id = (int) ($input["post_id"] ?? 0);
        $reaction = trim($input["reaction"] ?? 'like');

        $checkReact = "select reaction from post_reacts where user_id=? and post_id=?";
        $checkStmt = $conn->prepare($checkReact);
        $checkStmt->bind_param("ii", $user_id, $post_id);
        $checkStmt->execute();
        $checkResult = $checkStmt->get_result();
        if ($checkResult->num_rows > 0) { //check reaction is already exist?
            $existing = $checkResult->fetch_assoc();
            if ($existing['reaction'] === $reaction) {
                //delete react
                $deleteSql = "DELETE FROM post_reacts WHERE user_id = ? AND post_id = ?";
                $deleteStmt = $conn->prepare($deleteSql);
                $deleteStmt->bind_param("ii", $user_id, $post_id);
                $deleteStmt->execute();

                Response::json([
                    "status" => true,
                    "message" => "Reaction removed successfully"
                ]);
            } else {

                // Update
                $reactUpdate = $conn->prepare(
                    "UPDATE post_reacts SET reaction=? WHERE post_id=? AND user_id=?"
                );
                $reactUpdate->bind_param("sii", $reaction, $post_id, $user_id);
                $reactUpdate->execute();

                Response::json([
                    "status" => true,
                    "message" => "Update Successfully"
                ]);
            }

        }
        //insert react
        else {
            $sql = "Insert into post_reacts(post_id,user_id,reaction) values (?,?,?)";

            $stmtReact = $conn->prepare($sql);
            $stmtReact->bind_param("iis", $post_id, $user_id, $reaction);
            ;
            $stmtReact->execute();
            Response::json([
                "status" => true,
                "message" => "Added Successfully"
            ]);
        }
    }
    /* =====================================================
     *  Delete Post
     * ===================================================== */
    public static function postDelete()
    {
        $conn = Database::connect();
        // $post_id = (int) (Request::input("post_id") ?? 0);
        $post_id = $_GET["post_id"] ?? 0;
        $creator_id = Auth::getUser()["user_id"];

        if ($post_id == 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid Post"
            ], 400);
        }

        //check is_deleted
        $checkSql = "SELECT is_deleted FROM posts WHERE post_id = ? AND creator_user_id = ?";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bind_param("ii", $post_id, $creator_id);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Post not found"
            ]);
            return;
        }

        $row = $result->fetch_assoc();
        if ((int) $row['is_deleted'] === 1) {
            Response::json([
                "status" => false,
                "message" => "Post already deleted"
            ]);
            return;
        }

        $deletePost = "Update posts set is_deleted=1, updated_at=Now() where post_id=? and creator_user_id=? and is_deleted=0";
        $stmtPost = $conn->prepare($deletePost);
        $stmtPost->bind_param("ii", $post_id, $creator_id);
        $stmtPost->execute();
        if ($stmtPost->affected_rows == 0) {
            Response::json([
                "status" => false,
                "message" => "Post is not found"
            ]);
        } else {
            Response::json([
                "status" => true,
                "message" => "Successfully deleted"
            ]);
        }
    }


    /* =====================================================
     *  Insert Comment
     * ===================================================== */
    public static function commentPost()
    {
        $conn = Database::connect();
        $input = Request::json();
        $user = Auth::getUser();
        $user_id = $user["user_id"];

        // $post_id = (int) (Request::input("post_id") ?? 0);
        // $comment = trim(Request::input("comment") ?? null);
        $post_id = (int) $input["post_id"] ?? 0;
        $comment = trim($input["comment"] ?? null);

        if ($post_id == 0) {
            Response::json([
                "status" => false,
                "message" => "Cannot find post"
            ], 500);
        }
        $postSql = "SELECT post_id,is_banned from posts where post_id=?";
        $postStmt = $conn->prepare($postSql);
        $postStmt->bind_param("i", $post_id);
        $postStmt->execute();
        $post = $postStmt->get_result()->fetch_assoc();
        if ((int) $post['is_banned'] === 1) {
            Response::json([
                "status" => false,
                "message" => "you cannot comment this post(isBanned)"
            ]);
        }


        $sql = "Insert into post_comments(post_id,user_id,comment) values (?,?,?)";

        $stmtReact = $conn->prepare($sql);

        $stmtReact->bind_param("iis", $post_id, $user_id, $comment);

        $stmtReact->execute();
        $comment_id = $conn->insert_id;

        $sql = "SELECT 
                c.post_comment_id,
                c.comment,
                c.post_id,
                c.created_at,
                u.user_id,
                u.display_name,
                u.gender,
                u.profile_image
            FROM post_comments c
            JOIN users u ON c.user_id = u.user_id
            WHERE c.post_id = ? AND c.post_comment_id = ?
            AND c.is_deleted = 0";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ii", $post_id, $comment_id);
        $stmt->execute();
        $result = $stmt->get_result();

        $comment = $result->fetch_assoc();
        $comment["creator"] = [
            "id" => $comment["user_id"],
            "display_name" => $comment["display_name"],
            "gender" => $comment["gender"],
            "profile_image" => $comment["profile_image"]
        ];

        unset(
            $comment["user_id"],
            $comment["display_name"],
            $comment["gender"],
            $comment["profile_image"]
        );

        Response::json([
            "status" => true,
            "message" => "Added Successfully",
            "comment" => $comment
        ]);

    }

    /* =====================================================
     *  Comment Delete
     * ===================================================== */
    public static function commentDelete()
    {
        $conn = Database::connect();
        $user_id = (int) (Request::input("user_id") ?? 0);
        $post_comment_id = (int) (Request::input("post_comment_id") ?? 0);

        //check is_deleted
        $checkSql = "SELECT is_deleted FROM post_comments WHERE post_comment_id = ? AND user_id = ?";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bind_param("ii", $post_comment_id, $user_id);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Comment not found"
            ]);
            return;
        }

        $row = $result->fetch_assoc();
        if ((int) $row['is_deleted'] === 1) {
            Response::json([
                "status" => false,
                "message" => "Comment already deleted"
            ]);
            return;
        }

        $updateComment = "Update post_comments set is_deleted=1, updated_at=Now() where post_comment_id=? and user_id=? and is_deleted=0";
        $stmtComment = $conn->prepare($updateComment);
        $stmtComment->bind_param("ii", $user_id, $post_comment_id);
        $stmtComment->execute();
        if ($stmtComment->affected_rows == 0) {
            Response::json([
                "status" => false,
                "message" => "Comment and User are not found"
            ]);
        } else {
            Response::json([
                "status" => true,
                "message" => "Deleted Successfully"
            ]);
        }
    }

    /* =====================================================
     *  Get Comments
     * ===================================================== */
    public static function getComments($post_id)
    {
        $conn = Database::connect();
        // $post_id = (int) (Request::input("post_id") ?? 0);

        if ($post_id === 0) {
            Response::json([
                "status" => false,
                "message" => "post_id is required"
            ]);
            return;
        }

        $page = (int) $_GET["page"] ?? 1;

        $limit = 10;
        $offset = ($page - 1) * $limit;

        $sql = "
            SELECT 
                c.post_comment_id,
                c.comment,
                c.post_id,
                c.created_at,
                u.user_id,
                u.display_name,
                u.gender,
                u.profile_image,
                u.username
            FROM post_comments c
            JOIN users u ON c.user_id = u.user_id
            WHERE c.post_id = ?
            AND c.is_deleted = 0
            ORDER BY c.created_at DESC
            LIMIT ? OFFSET ?
        ";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iii", $post_id, $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();

        $comments = [];

        while ($row = $result->fetch_assoc()) {
            $row["creator"] = [
                "id" => $row["user_id"],
                "display_name" => $row["display_name"],
                "gender" => $row["gender"],
                "profile_image" => $row["profile_image"],
                "username" => $row["username"]
            ];

            unset(
                $row["user_id"],
                $row["display_name"],
                $row["gender"],
                $row["profile_image"],
                $row["username"]
            );

            $comments[$row["post_comment_id"]] = $row;
        }

        $comment_count = self::getCommentCount($post_id);
        $total_page = ceil($comment_count / $limit);

        Response::json([
            "status" => true,
            "page" => $page,
            "total_page" => $total_page,
            "data" => array_values($comments),
        ]);
    }
    public static function getPostsByFriends()
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = (int) ($user["user_id"] ?? 0);
        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
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

                u.display_name,
                u.gender,
                u.profile_image,
                u.username,

                COUNT(DISTINCT r.post_react_id) AS react_count,
                COUNT(DISTINCT c.post_comment_id) AS comment_count,
                (COUNT(DISTINCT r.post_react_id) + COUNT(DISTINCT c.post_comment_id)) AS total_engagement,

                -- Weighted engagement
                (
                    COUNT(DISTINCT r.post_react_id) * 1 +
                    COUNT(DISTINCT c.post_comment_id) * 3
                ) AS weighted_engagement,

                -- Feed ranking score (engagement + time decay)
                (
                    (
                        COUNT(DISTINCT r.post_react_id) * 1 +
                        COUNT(DISTINCT c.post_comment_id) * 3
                    ) 
                    /
                    POW(TIMESTAMPDIFF(HOUR, p.created_at, NOW()) + 2, 1.4)
                ) AS feed_score,

                CASE 
                    WHEN COUNT(ur.post_react_id) > 0 THEN 1
                    ELSE 0
                END AS is_liked,

                MAX(ur.reaction) AS reaction

                FROM posts p
                JOIN users u
                    ON u.user_id = p.creator_user_id
                LEFT JOIN post_reacts r
                    ON r.post_id = p.post_id
                LEFT JOIN post_comments c
                    ON c.post_id = p.post_id

                LEFT JOIN post_reacts ur
                    ON ur.post_id = p.post_id
                    AND ur.user_id = ?

                LEFT JOIN hide_posts hp
                    ON hp.post_id = p.post_id
                    AND hp.user_id = ?

                JOIN friends f
    ON (
        (f.user_1_id = p.creator_user_id AND f.user_2_id = ?)
        OR (f.user_2_id = p.creator_user_id AND f.user_1_id = ?)
    )
    AND f.status = 'accepted'
                WHERE p.is_deleted = 0
    AND p.is_archived = 0
    AND p.is_draft = 0
    AND p.is_banned = 0
  AND u.is_active = 1
    AND p.creator_user_id != ?


                    GROUP BY p.post_id
                    ORDER BY total_engagement DESC, p.created_at DESC
                    LIMIT ? OFFSET ?

        ";
        $stmtSave = $conn->prepare($sql);
        $stmtSave->bind_param("iiiiiii",  $user_id, $user_id, $user_id, $user_id, $user_id, $limit, $offset);
        $stmtSave->execute();

        if ($stmtSave->error) {
            Response::json(["status" => false, "error" => $stmtSave->error]);
            return;
        }

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
            $row["tagged_users"] = [];
            $posts[$row['post_id']] = $row;
        }

        PostController::attachAttachments($conn, $posts);
        self::attachTaggedUsers($conn, $posts);

        $totalPosts = PostController::getFriendsPostCount($user_id);
        $totalPages = ceil($totalPosts / $limit);

        Response::json([
            "status" => true,
            "page" => $page,
            "totalPages" => $totalPages,
            "data" => array_values($posts)
        ]);

    }

    /* =====================================================
     * Tag Post
     * ===================================================== */
    public static function tagPost()
    {
        $conn = Database::connect();
        $post_id = (int) (Request::input("post_id") ?? 0);
        $tagged_user_ids = Request::input("tagged_user_id") ?? [];

        //check the post or user
        if ($post_id <= 0 || !is_array($tagged_user_ids) || empty($tagged_user_ids)) {
            Response::json([
                "status" => false,
                "message" => "Invalid post or user"
            ]);
            return;
        }

        // Check if post exists
        $sql = "SELECT post_id FROM posts WHERE post_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $post_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Post is not found"
            ]);
            return;
        }

        $alreadyTagged = [];

        // Start transaction
        $conn->begin_transaction();

        try {
            $insertStmt = $conn->prepare(
                "INSERT INTO post_tags (post_id, tagged_user_id) VALUES (?, ?)"
            );

            $checkStmt = $conn->prepare(
                "SELECT post_tag_id FROM post_tags WHERE post_id = ? AND tagged_user_id = ?"
            );

            foreach ($tagged_user_ids as $user_id) {
                $user_id = (int) $user_id;
                if ($user_id <= 0)
                    continue;

                // Check if already tagged
                $checkStmt->bind_param("ii", $post_id, $user_id);
                $checkStmt->execute();
                $checkResult = $checkStmt->get_result();

                if ($checkResult->num_rows > 0) {
                    $alreadyTagged[] = $user_id;
                    continue; // Skip inserting
                }

                // Insert tag
                $insertStmt->bind_param("ii", $post_id, $user_id);
                $insertStmt->execute();
            }

            $conn->commit();

            if (!empty($alreadyTagged)) {
                Response::json([
                    "status" => false,
                    "message" => "These users are already tagged: " . implode(", ", $alreadyTagged)
                ]);
            } else {
                Response::json([
                    "status" => true,
                    "message" => "Users tagged successfully"
                ]);
            }

        } catch (Exception $e) {
            $conn->rollback();
            Response::json([
                "status" => false,
                "message" => "Failed to tag users"
            ]);
        }
    }

    /* =====================================================
     * Update Tag Post
     * ===================================================== */
    public static function updateTagPost()
    {
        $conn = Database::connect();

        $post_id = (int) (Request::input("post_id") ?? 0);
        $tagged_user_ids = Request::input("tagged_user_id") ?? [];

        // Validate input
        if ($post_id <= 0 || !is_array($tagged_user_ids)) {
            Response::json([
                "status" => false,
                "message" => "Invalid post or user"
            ]);
            return;
        }

        // Check if post exists
        $stmt = $conn->prepare("SELECT post_id FROM posts WHERE post_id = ?");
        $stmt->bind_param("i", $post_id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Post not found"
            ]);
            return;
        }

        // Start transaction
        $conn->begin_transaction();

        try {
            //remove already post tags
            $deleteStmt = $conn->prepare(
                "DELETE FROM post_tags WHERE post_id = ?"
            );
            $deleteStmt->bind_param("i", $post_id);
            $deleteStmt->execute();

            /**
             * STEP 2: Insert new tags
             */
            $insertStmt = $conn->prepare(
                "INSERT INTO post_tags (post_id, tagged_user_id) VALUES (?, ?)"
            );

            foreach ($tagged_user_ids as $user_id) {
                $user_id = (int) $user_id;
                if ($user_id <= 0) {
                    continue;
                }

                $insertStmt->bind_param("ii", $post_id, $user_id);
                $insertStmt->execute();
            }

            $conn->commit();

            Response::json([
                "status" => true,
                "message" => "Post tags updated successfully"
            ]);

        } catch (Exception $e) {
            $conn->rollback();
            Response::json([
                "status" => false,
                "message" => "Failed to update post tags"
            ]);
        }
    }


    /* =====================================================
     * Delete Tag Post
     * ===================================================== */
    public static function deleteTagPost()
    {
        $conn = Database::connect();

        $post_id = (int) (Request::input("post_id") ?? 0);
        $tagged_user_id = (int) (Request::input("tagged_user_id") ?? 0);

        // Validate input
        if ($post_id <= 0 || $tagged_user_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid  post or user"
            ]);
            return;
        }

        // Check if tag exists
        $checkStmt = $conn->prepare(
            "SELECT post_tag_id FROM post_tags WHERE post_id = ? and tagged_user_id=?"
        );
        $checkStmt->bind_param("ii", $post_id, $tagged_user_id);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Tag post not found"
            ]);
            return;
        }

        // Delete tag
        $deleteStmt = $conn->prepare(
            "DELETE FROM post_tags WHERE post_id = ? and tagged_user_id=?"
        );
        $deleteStmt->bind_param("ii", $post_id, $tagged_user_id);
        $deleteStmt->execute();

        Response::json([
            "status" => true,
            "message" => "Tag removed successfully"
        ]);
    }

    /* =====================================================
     * Get Tag Post
     * ===================================================== */
    public static function getTagPost()
    {
        $conn = Database::connect();

        $post_id = (int) (Request::input("post_id") ?? 0);

        $page = isset($_GET['page']) ? max(1, (int) $_GET['page']) : 1;
        $limit = 5;
        $offset = ($page - 1) * $limit;

        if ($post_id <= 0) {
            Response::json([
                "status" => false,
                "message" => "Invalid post id"
            ]);
            return;
        }

        // Check post exists
        $stmt = $conn->prepare("SELECT post_id FROM posts WHERE post_id = ?");
        $stmt->bind_param("i", $post_id);
        $stmt->execute();

        if ($stmt->get_result()->num_rows === 0) {
            Response::json([
                "status" => false,
                "message" => "Post not found"
            ]);
            return;
        }

        // Get total tagged users
        $countStmt = $conn->prepare(
            "SELECT COUNT(*) AS total
            FROM post_tags
            WHERE post_id = ?"
        );
        $countStmt->bind_param("i", $post_id);
        $countStmt->execute();
        $total = (int) $countStmt->get_result()->fetch_assoc()['total'];


        $tagStmt = $conn->prepare(
            "SELECT 
                u.user_id,
                u.username,
                u.display_name
            FROM post_tags pt
            INNER JOIN users u ON u.user_id = pt.tagged_user_id
            WHERE pt.post_id = ?
            ORDER BY pt.post_tag_id DESC
            LIMIT ? OFFSET ?"
        );

        $tagStmt->bind_param("iii", $post_id, $limit, $offset);
        $tagStmt->execute();
        $result = $tagStmt->get_result();

        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }

        Response::json([
            "status" => true,
            "post_id" => $post_id,
            "pagination" => [
                "page" => $page,
                "limit" => $limit,
                "total" => $total,
                "total_pages" => ceil($total / $limit)
            ],
            "users" => $users
        ]);
    }

    /* =====================================================
     * Count helpers
     * ===================================================== */
    public static function getPostCount($userId = 0)
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $user_id = $user?->user_id ?? 0;

        if ($userId === 0) {
            // Count all posts excluding hidden ones for the current user
            $sql = "
            SELECT COUNT(DISTINCT p.post_id) AS total
            FROM posts p
            LEFT JOIN hide_posts hp
                ON hp.post_id = p.post_id
               AND hp.user_id = ?
            WHERE p.is_deleted = 0
              AND p.is_archived = 0
              AND hp.post_id IS NULL
        ";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();

            return $row ? (int) $row['total'] : 0;
        }

        // Count posts for a specific user (no hidden post filter needed here)
        $stmt = $conn->prepare("
        SELECT COUNT(*) AS total 
        FROM posts 
        WHERE is_deleted = 0 AND creator_user_id = ?
    ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();

        return (int) $result->fetch_assoc()['total'];
    }

    public static function getFriendsPostCount($userId = 0)
    {
        $conn = Database::connect();

        if ($userId === 0) {
            $stmt = $conn->prepare("SELECT COUNT(*) AS total FROM posts p JOIN users u ON u.user_id = p.creator_user_id JOIN friends f ON (f.user_1_id = ? AND f.user_2_id = p.creator_user_id) OR (f.user_2_id = ? AND f.user_1_id = p.creator_user_id) WHERE is_deleted = 0");

            $stmt->bind_param("ii", $userId, $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            return (int) $result->fetch_assoc()["total"];
        }
    }

    private static function getFollowingPostCount($userId)
    {
        $conn = Database::connect();

        $stmt = $conn->prepare("SELECT COUNT(DISTINCT p.post_id) AS total
        FROM posts p
        INNER JOIN follows f ON f.following_user_id = p.creator_user_id 
            AND f.follower_user_id = ?
        LEFT JOIN hide_posts hp ON hp.post_id = p.post_id
            AND hp.user_id = ?  -- Current user hiding posts
        WHERE (p.is_deleted = 0 AND p.is_archived = 0)
          AND hp.post_id IS NULL  -- Exclude hidden posts
        ");

        // $stmt = $conn->prepare($stmt);
        $stmt->bind_param("ii", $userId, $userId);
        $stmt->execute();
        $result = $stmt->get_result();

        return (int) $result->fetch_assoc()['total'];
    }

    private static function getPostCountByUsername($username)
    {
        $conn = Database::connect();
        $user = Auth::getUser();
        $current_user_id = $user?->user_id ?? 0;

        $stmt = $conn->prepare(" SELECT COUNT(DISTINCT p.post_id) AS total
            FROM posts p
            JOIN users u 
                ON u.user_id = p.creator_user_id
            LEFT JOIN hide_posts hp
                ON hp.post_id = p.post_id
               AND hp.user_id = ?
            WHERE u.username = ?
              AND p.is_deleted = 0
              AND p.is_archived = 0
              AND hp.post_id IS NULL
    ");

        $stmt->bind_param("is", $current_user_id, $username);
        $stmt->execute();

        $result = $stmt->get_result();
        return (int) $result->fetch_assoc()["total"];
    }

    private static function getCommentCount($post_id)
    {
        $conn = Database::connect();

        $sql = "SELECT COUNT(*) AS total_comments
                    FROM post_comments
                    WHERE post_id = ?
                    AND is_deleted = 0;";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $post_id);
        $stmt->execute();

        $result = $stmt->get_result();
        return (int) $result->fetch_assoc()["total_comments"];
    }

}