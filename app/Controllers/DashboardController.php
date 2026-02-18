<?php
namespace App\Controllers;

use App\Core\AdminAuth;
use App\Core\Database;
use App\Core\Response;

class DashboardController
{
    public static function getDashboard()
    {
        $conn = Database::connect();

        // Check admin login
        $admin = AdminAuth::admin();

        if (!$admin) {
            Response::json([
                "status" => false,
                "message" => "Not authorized"
            ], 401);
            return;
        }
        $admin_id = $admin["admin_id"] ?? null;

        try {

            /* ------------------ Cards ------------------ */

            // Total Users
            $totalUsers = $conn->query("
                SELECT COUNT(*) AS total
                FROM users
                WHERE deleted_account = 0
            ")->fetch_assoc()["total"];

            // Daily Active Users
            $dailyUsers = $conn->query("
                SELECT COUNT(*) AS total
                FROM users
                WHERE DATE(last_seen) = CURDATE()
            ")->fetch_assoc()["total"];

            // Average users per day (last 7 days)
            $avgUsersResult = $conn->query("
                SELECT AVG(daily_count) AS avgUsers
                FROM (
                    SELECT DATE(created_at) AS day, COUNT(*) AS daily_count
                    FROM users
                    WHERE created_at >= CURDATE() - INTERVAL 7 DAY
                    GROUP BY DATE(created_at)
                ) t
            ")->fetch_assoc();

            $avgUsers = round($avgUsersResult["avgUsers"] ?? 0, 2);

            // Total Posts
            $totalPosts = $conn->query("
                SELECT COUNT(*) AS total
                FROM posts
                WHERE is_deleted = 0
            ")->fetch_assoc()["total"];

            // Total Reports
            $totalReports = $conn->query("
                SELECT COUNT(*) AS total
                FROM reported_posts
            ")->fetch_assoc()["total"];

            // Pending Reports
            $pendingReports = $conn->query("
                SELECT COUNT(*) AS total
                FROM reported_posts
                WHERE status = 'pending'
            ")->fetch_assoc()["total"];


            /* ------------------ User Growth ------------------ */

            $userGrowthResult = $conn->query("
                SELECT DATE(created_at) AS date, COUNT(*) AS count
                FROM users
                WHERE created_at >= CURDATE() - INTERVAL 7 DAY
                GROUP BY DATE(created_at)
                ORDER BY date
            ");

            $userGrowth = [];
            while ($row = $userGrowthResult->fetch_assoc()) {
                $userGrowth[] = $row;
            }


            /* ------------------ Posts Created ------------------ */

            $postsCreatedResult = $conn->query("
                SELECT DATE(created_at) AS date, COUNT(*) AS count
                FROM posts
                WHERE created_at >= CURDATE() - INTERVAL 7 DAY
                AND is_deleted = 0
                GROUP BY DATE(created_at)
                ORDER BY date
            ");

            $postsCreated = [];
            while ($row = $postsCreatedResult->fetch_assoc()) {
                $postsCreated[] = $row;
            }


            /* ------------------ Images Uploaded ------------------ */

            $imagesUploadedResult = $conn->query("
                SELECT DATE(p.created_at) AS date, COUNT(*) AS count
                FROM post_attachments pa
                JOIN posts p ON p.post_id = pa.post_id
                WHERE pa.type = 'image'
                AND p.created_at >= CURDATE() - INTERVAL 7 DAY
                GROUP BY DATE(p.created_at)
                ORDER BY date
            ");

            $imagesUploaded = [];
            while ($row = $imagesUploadedResult->fetch_assoc()) {
                $imagesUploaded[] = $row;
            }


            /* ------------------ Reaction Distribution ------------------ */

            $reactionResult = $conn->query("
                SELECT reaction, COUNT(*) AS count
                FROM post_reacts
                GROUP BY reaction
                ORDER BY count DESC
            ");

            $reactionDistribution = [];
            $totalReacts = 0;

            while ($row = $reactionResult->fetch_assoc()) {
                $totalReacts += $row["count"];
                $reactionDistribution[] = $row;
            }

            foreach ($reactionDistribution as &$reaction) {
                $reaction["percentage"] = $totalReacts > 0
                    ? round(($reaction["count"] / $totalReacts) * 100, 2)
                    : 0;
            }


            /* ------------------ Reports Trend ------------------ */

            $reportsTrendResult = $conn->query("
                SELECT DATE(reported_at) AS date, COUNT(*) AS count
                FROM reported_posts
                WHERE reported_at >= CURDATE() - INTERVAL 7 DAY
                GROUP BY DATE(reported_at)
                ORDER BY date
            ");

            $reportsTrend = [];
            while ($row = $reportsTrendResult->fetch_assoc()) {
                $reportsTrend[] = $row;
            }


            /* ------------------ Response ------------------ */

            Response::json([
                "status" => true,
                "data" => [
                    "cards" => [
                        "totalUsers" => (int)$totalUsers,
                        "dailyUsers" => (int)$dailyUsers,
                        "averageUsers" => (float)$avgUsers,
                        "totalPosts" => (int)$totalPosts,
                        "totalReports" => (int)$totalReports,
                        "pendingReports" => (int)$pendingReports
                    ],
                    "userGrowth" => $userGrowth,
                    "postsCreated" => $postsCreated,
                    "imagesUploaded" => $imagesUploaded,
                    "reactionDistribution" => $reactionDistribution,
                    "reportsTrend" => $reportsTrend
                ]
            ]);

        } catch (\Exception $e) {
            Response::json([
                "status" => false,
                "message" => "Dashboard error",
                "error" => $e->getMessage()
            ], 500);
        }
    }
}