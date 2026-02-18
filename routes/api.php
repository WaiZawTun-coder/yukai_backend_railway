<?php

use App\Controllers\AdminController;
use App\Controllers\AuthController;
use App\Controllers\DashboardController;
use App\Controllers\DeviceController;
use App\Controllers\FriendController;
use App\Controllers\NotificationController;
use App\Controllers\PostController;
use App\Controllers\PostHidingController;
use App\Controllers\UserController;
use App\Controllers\SaveController;
use App\Controllers\SearchController;
use App\Controllers\ChatController;
use App\Controllers\MessageController;
use App\Controllers\ReportController;


use App\Controllers\LoginHistoriesController;
use App\Controllers\ImageController;
use App\Controllers\PrivacyController;


use App\Core\Auth;


/*
|--------------------------------------------------------------------------
| Public Routes
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/",
    fn() =>
    print json_encode(["status" => true, "message" => "success"]),
    false
);

Router::add(
    "POST",
    "/auth/login",
    fn() =>
    AuthController::login(),
    false
);

Router::add(
    "POST",
    "/auth/logout",
    fn() => AuthController::logout(),
    true
);

Router::add(
    "POST",
    "/auth/register",
    fn() =>
    AuthController::register(),
    false
);

Router::add(
    "POST",
    "/auth/register/{username}",
    fn($username) =>
    AuthController::register($username),
    true
);

Router::add(
    "POST",
    "/auth/refresh",
    fn() =>
    AuthController::refresh(),
    false
);

Router::add(
    "POST",
    "/auth/forget-password",
    fn() =>
    AuthController::forgetPassword(),
    false
);

Router::add(
    "POST",
    "/auth/reset-password",
    fn() =>
    AuthController::resetPassword(),
    false
);


/*
|--------------------------------------------------------------------------
| User & Profile
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/api/get-user",
    fn() =>
    UserController::getUser(),
    true
);

Router::add(
    "GET",
    "/api/profile",
    fn() =>
    AuthController::index(),
    true
);

Router::add(
    "POST",
    "/api/edit-user",
    fn() =>
    UserController::editUser(),
    true
);
Router::add(
    "POST",
    "/api/upload-image",
    fn() => ImageController::uploadImage(),
    true
);

Router::add(
    "POST",
    "/api/request-password-otp",
    fn() =>
    UserController::requestPasswordOTP(),
    true
);

Router::add(
    "POST",
    "/api/change-password",
    fn() =>
    UserController::changepassword(),
    true
);
Router::add(
    "POST",
    "/api/generate-otp-api",
    fn() => UserController::generateOTPApi(), // or AuthController::generateOTPApi
    true
);

Router::add(
    "POST",
    "/api/deactivate-user",
    fn() =>
    UserController::deactivateUser(),
    true
);

Router::add(
    "POST",
    "/api/deleted-account",
    fn() =>
    UserController::deletedAccount(),
    true
);

Router::add(
    "GET",
    "/api/deactivate-account",
    fn() =>
    UserController::deactivateAccount(),
    true
);


/*
|--------------------------------------------------------------------------
| Posts
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/api/get-posts",
    fn() =>
    PostController::getPosts(),
    true
);

Router::add(
    "GET",
    "/api/get-user-post/{username}",
    fn($username) =>
    PostController::getPostsByUsername($username),
    true
);

Router::add(
    "GET",
    "/api/get-following-post",
    fn() =>
    PostController::getFollowingPosts(),
    true
);

Router::add(
    "GET",
    "/api/get-friends-posts",
    fn() =>
    PostController::getPostsByFriends(),
    true
);

Router::add(
    "GET",
    "/api/get-post",
    fn() =>
    PostController::getPostsByPostId(),
    true
);

Router::add(
    "GET",
    "/api/get-draft-post",
    fn() =>
    PostController::getDraftedPost(),
    true
);

Router::add(
    "POST",
    "/api/create-post",
    fn() =>
    PostController::createPost(),
    true
);

Router::add(
    "GET",
    "/api/edit-post",
    fn() =>
    PostController::editPost(),
    true
);

Router::add(
    "GET",
    "/api/edit-post-privacy",
    fn() =>
    PostController::editPostPrivacy(),
    true
);

Router::add(
    "POST",
    "/api/react-post",
    fn() =>
    PostController::reactPost(),
    true
);

Router::add(
    "POST",
    "/api/comment-post",
    fn() =>
    PostController::commentPost(),
    true
);

Router::add(
    "DELETE",
    "/api/delete-comment",
    fn() =>
    PostController::commentDelete(),
    true
);

Router::add(
    "GET",
    "/api/get-comment/{post_id}",
    fn($post_id) =>
    PostController::getComments($post_id),
    true
);

Router::add(
    "DELETE",
    "/api/delete-post",
    fn() =>
    PostController::postDelete(),
    true
);

Router::add(
    "POST",
    "/api/edit-history",
    fn() =>
    PostController::editHistory(),
    true
);

Router::add(
    "GET",
    "/api/get-edit-history",
    fn() =>
    PostController::getEditHistory(),
    true
);


/*
|--------------------------------------------------------------------------
| Post Hiding
|--------------------------------------------------------------------------
*/

Router::add(
    "POST",
    "/api/hide-post",
    fn() =>
    PostHidingController::hidePost(),
    true
);

Router::add(
    "POST",
    "/api/unhide-post",
    fn() =>
    PostHidingController::unhidePost(),
    true
);
/*
|--------------------------------------------------------------------------
| Post Tag
|--------------------------------------------------------------------------
*/

Router::add(
    "POST",
    "/api/tag-post",
    fn() =>
    PostController::tagPost(),
    true
);
Router::add(
    "GET",
    "/api/update-tag-post",
    fn() =>
    PostController::updateTagPost(),
    true
);
Router::add(
    "GET",
    "/api/delete-tag-post",
    fn() =>
    PostController::deleteTagPost(),
    true
);
Router::add(
    "GET",
    "/api/get-tag-post",
    fn() =>
    PostController::getTagPost(),
    true
);


/*
|--------------------------------------------------------------------------
| Friends / Follow
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/api/get-friends",
    fn() =>
    FriendController::getFriends(),
    true
);

Router::add("GET", "/api/get-following", fn() => FriendController::getFollowings(), true);

Router::add("GET", "/api/get-followers", fn() => FriendController::getFollowers(), true);

Router::add(
    "POST",
    "/api/send-request",
    fn() =>
    FriendController::sendFriendRequest(),
    true
);

Router::add(
    "POST",
    "/api/response-request",
    fn() =>
    FriendController::responseFriendRequest(),
    true
);

Router::add(
    "GET",
    "/api/get-sent-requests",
    fn() =>
    FriendController::getFriendRequest(),
    true
);

Router::add(
    "GET",
    "/api/get-received-requests",
    fn() =>
    FriendController::getReceivedRequests(),
    true
);

Router::add(
    "GET",
    "/api/get-people-you-may-know",
    fn() =>
    FriendController::peopleYouMayKnow(),
    true
);

Router::add(
    "POST",
    "/api/follow",
    fn() =>
    FriendController::followUser(),
    true,
);

Router::add(
    "POST",
    "/api/unfollow",
    fn() =>
    FriendController::unfollowUser(),
    true,
);

Router::add(
    "POST",
    "/api/block-user",
    fn() =>
    FriendController::blockUser(),
    true,
);

Router::add(
    "POST",
    "/api/unblock",
    fn() =>
    FriendController::unblockUser(),
    true,
);

Router::add(
    "GET",
    "/api/getBlock-lists",
    fn() =>
    FriendController::getBlockLists(),
    true
);

Router::add(
    "POST",
    "/api/unfriend",
    fn() =>
    FriendController::unfriend(),
    true
);


/*
|--------------------------------------------------------------------------
| Saved Posts
|--------------------------------------------------------------------------
*/

Router::add(
    "POST",
    "/api/create-saved-list",
    fn() =>
    SaveController::createSavedLists(),
    true
);

Router::add(
    "POST",
    "/api/save-post",
    fn() =>
    SaveController::createSavedPosts(),
    true
);

Router::add(
    "GET",
    "/api/get-saved-lists",
    fn() =>
    SaveController::getSavedLists(),
    true
);

Router::add(
    "GET",
    "/api/get-saved-posts/{list_id}",
    fn($list_id) =>
    SaveController::getSavedPosts($list_id),
    true
);

Router::add(
    "GET",
    "/api/update-saved-posts",
    fn() =>
    SaveController::updateSavedPosts(),
    true
);

Router::add(
    "GET",
    "/api/delete-saved-posts",
    fn() =>
    SaveController::deleteSavedPosts(),
    true
);


/*
|--------------------------------------------------------------------------
| Search
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/api/search",
    fn() =>
    SearchController::search(),
    true
);


/*
|--------------------------------------------------------------------------
| Chats
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/api/chats",
    fn() =>
    ChatController::getMyChats(),
    true
);

Router::add(
    "GET",
    "/api/chat",
    fn() =>
    ChatController::getChat(),
    true
);

Router::add(
    "GET",
    "/api/get-group-chat",
    fn() =>
    ChatController::getChatById(),
    true
);

Router::add(
    "POST",
    "/api/chats/private",
    fn() =>
    ChatController::createPrivateChat(),
    true
);

Router::add(
    "POST",
    "/api/chats/group",
    fn() =>
    ChatController::createGroupChat(),
    true
);

Router::add(
    "GET",
    "/api/chats/participants",
    fn() =>
    ChatController::getParticipants(),
    true
);

Router::add(
    "POST",
    "/api/chats/add-participants",
    fn() => ChatController::addParticipants(),
    true
);

Router::add(
    "POST",
    "/api/chats/leave",
    fn() =>
    ChatController::leaveChat(),
    true
);

Router::add(
    "POST",
    "/api/chats/delete",
    fn() =>
    ChatController::deleteChat(),
    true
);

Router::add(
    "POST",
    "/api/chats/mute",
    fn() => ChatController::muteChat(),
    true
);


/*
|--------------------------------------------------------------------------
| Messages
|--------------------------------------------------------------------------
*/

Router::add(
    "GET",
    "/api/chat/get-messages",
    fn() =>
    MessageController::getMessages(),
    true
);

Router::add(
    "POST",
    "/api/chat/send-message",
    fn() =>
    MessageController::sendMessage(),
    true
);

Router::add(
    "POST",
    "/api/chat/edit-message",
    fn() =>
    MessageController::editMessage(),
    true
);

Router::add(
    "POST",
    "/api/chat/delete-message",
    fn() =>
    MessageController::deleteMessage(),
    true
);

Router::add(
    "POST",
    "/api/chat/update-receipt",
    fn() =>
    MessageController::updateReceipt(),
    true
);


/*
|--------------------------------------------------------------------------
| Devices & Keys
|--------------------------------------------------------------------------
*/


Router::add("GET", "/api/get-saved-posts/{list_id}", function ($list_id) {
    SaveController::getSavedPosts($list_id);
}, true); // get Saved Posts

Router::add("GET", "/api/update-saved-posts", function () {
    SaveController::updateSavedPosts();
}, true); // update saved posts

Router::add("GET", "/api/delete-saved-posts", function () {
    SaveController::deleteSavedPosts();
}, true);

//friends
Router::add("POST", "/api/send-request", function () {
    FriendController::sendFriendRequest();
}, true);//send friend requent
Router::add("POST", "/api/response-request", function () {
    FriendController::responseFriendRequest();
}, true);//accept,reject,cancel friend request
Router::add("GET", "/api/get-sent-requests", function () {
    FriendController::getFriendRequest();
}, true);//get Friend Request
Router::add("GET", "/api/get-received-requests", function () {
    FriendController::getReceivedRequests();
}, true);
Router::add("GET", "/api/get-people-you-may-know", function () {
    FriendController::peopleYouMayKnow();
}, true);
// delete saved posts

// Router::add("POST", "/auth/generateOTP", function () {
// AuthController::generateOTP();
// }, true); // generate otp 

Router::add("POST", "/auth/verify-otp", function () {
    AuthController::verifyOTPRoute();
}, true); // verify otp

// Router::add("POST", "/auth/send-email", function () {
// AuthController::sendEmail();
// }, false); // send email

//passwords
// Router::add("POST", "/auth/forget-password", function () {
//     AuthController::forgetPassword();
// }, true); // forget password

Router::add("POST", "/auth/reset-password", function () {
    AuthController::resetPassword();
}, true); // reset password


//followers
Router::add("POST", "/api/follow", function () {
    FriendController::followUser();
}, false);
Router::add("POST", "/api/unfollow", function () {
    FriendController::unfollowUser();
}, false);
Router::add("POST", "/api/block-user", function () {
    FriendController::blockUser();
}, false);
Router::add("POST", "/api/unblock", function () {
    FriendController::unblockUser();
}, false);
Router::add("POST", "/api/unfriend", function () {
    FriendController::unfriend();
}, false);



Router::add("POST", "/api/search", function () {
    SearchController::search();
}, true); // search 
//chatting
Router::add("POST", "/api/Chatting", function () {

    ChatController::createPrivateChat();
}, true);
Router::add("POST", "/api/auth/2factors", function () {

    ChatController::createPrivateChat();
}, true);
Router::add("POST", "/api/auth/2factors", function () {

    AuthController::twoFactorAuthentication();
}, false);

Router::add(
    "POST",
    "/api/register-device",
    fn() =>
    DeviceController::registerDevice(),
    true
);

Router::add("GET", "/api/device-status", function () {
    DeviceController::getDeviceStatus();
}, true);

Router::add("POST", "/api/reset-device", function () {
    DeviceController::resetDevice();
}, true);

Router::add(
    "GET",
    "/api/get-public-keys",
    fn() =>
    DeviceController::getPublicKeys(),
    true
);
//report post
Router::add(
    "POST",
    "/api/report-post",
    fn() =>
    ReportController::reportPost(),
    true
);

Router::add(
    "POST",
    "/api/report-account",
    fn() =>
    ReportController::reported_acc(),
    true
);
/* ------get all reported posts----- */
Router::add(
    "GET",
    "/api/get-reported-posts",
    fn() =>
    ReportController::getReporPosts(),
    true
);

/* ------get all reported accounts----- */
Router::add(
    "GET",
    "/api/get-reported-accounts",
    fn() =>
    ReportController::getReportedAccounts(),
    true
);
/* ======= Admin Controller ================*/
/* ------control accounts----- */
Router::add(
    "GET",
    "/api/control-account",
    fn() =>
    AdminController::updateAccountStatus(),
    true
);

Router::add("POST", "/auth/admin/refresh", fn() => AdminController::refresh(), false);

Router::add("GET", "/api/admin/profile", fn() => AdminController::getProfile(), true);

Router::add(
    "GET",
    "/api/admin/dashboard",
    fn() => DashboardController::getDashboard(),
    true
);

/* ------Get All Admin accounts----- */
Router::add(
    "GET",
    "/api/get-admin-lists",
    fn() =>
    AdminController::getAdminLists(),
    true
);

/* ------Super Admin ban admin(moderator)---- */
Router::add(
    "POST",
    "/api/ban-admin",
    fn() =>
    AdminController::banAdmin(),
    true
);

Router::add("POST", "/api/unban-admin", fn() => AdminController::unbanAdmin(), true);

Router::add(
    "POST",
    "/auth/admin/register",
    fn() =>
    AdminController::AdminRegister(),
    true
);
Router::add(
    "POST",
    "/auth/admin-login",
    fn() =>
    AdminController::AdminLogin(),
    false
);

Router::add(
    "POST",
    "/auth/admin/setup-password",
    fn() => AdminController::setPassword(),
    false
);

Router::add(
    "POST",
    "/auth/admin/forget-password",
    fn() =>
    AdminController::forgetPassword(),
    false
);
Router::add("POST", "/auth/admin/logout", fn() => AdminController::logout(), true);

Router::add("GET", "/api/admin/get-users", fn() => AdminController::getUsers(), true);

//Admin

Router::add(
    "POST",
    "/api/reset-password",
    fn() =>
    AdminController::resetPassword(),
    false
);
Router::add(
    "POST",
    "/api/ban-user",
    fn() =>
    AdminController::banUser(),
    true
);

Router::add(
    "POST",
    "/api/unban-user",
    fn() => AdminController::unbanUser(),
    true
);

Router::add(
    "POST",
    "/api/warn-user",
    fn() => AdminController::warnUser(),
    true
);

Router::add(
    "POST",
    "/api/remove-warn-user",
    fn() => AdminController::removeWarnUser(),
    true
);

Router::add(
    "POST",
    "/api/suspend-user",
    fn() => AdminController::suspendUser(),
    true
);

Router::add(
    "POST",
    "/api/unsuspend-user",
    fn() => AdminController::unsuspendUser(),
    true
);

Router::add(
    "POST",
    "/api/ban-post",
    fn() =>
    AdminController::banPost(),
    true
);

Router::add(
    "POST",
    "/api/unban-post",
    fn() => AdminController::unbanPost(),
    true
);

Router::add(
    "POST", 
    "/api/update-post-report-status", 
    fn() => AdminController::updateReportStatus(), 
    true
);

Router::add(
    "POST",
    "/api/update-account-report-status",
    fn() => ReportController::updateAccountReportStatus(),
    true,
);

Router::add(
    "POST",
    "/api/edit-admin-profile",
    fn() =>
    AdminController::editAdminProfile(),
    true
);

Router::add(
    "POST",
    "/api/check-admin-password",
    fn() => AdminController::checkAdminPassword(), 
    true
);

Router::add(
    "POST",
    "/api/change-admin-password",
    fn() => AdminController::updateAdminPassword(),
    true
);

/*
|--------------------------------------------------------------------------
| Login Histories
|--------------------------------------------------------------------------
*/

// Router::add(
//     "GET",
//     "/api/login-histories",
//     fn() =>
//     LoginHistoriesController::loginHistories(),
//     true
// );

Router::add(
    "GET",
    "/api/get-login-histories",
    fn() =>
    LoginHistoriesController::getLoginHistories(),
    true
);

Router::add(
    "GET",
    "/api/get-notifications",
    fn() => NotificationController::getNotifications(),
    true
);

Router::add(
    "POST",
    "/api/add-notification",
    fn() => NotificationController::addNotification(),
    true
);

Router::add(
    "POST",
    "/api/mark-notification-read",
    fn() => NotificationController::updateStatus(),
    true
);

Router::add(
    "POST",
    "/api/mark-notifications-read",
    fn() => NotificationController::markAllAsRead(),
    true
);
// Add these routes:
Router::add(
    "GET",
    "/api/user/privacy/default",
    fn() => PrivacyController::getDefault(),
    true
);

Router::add(
    "POST",
    "/api/user/privacy/default",
    fn() => PrivacyController::updateDefault(),
    true
);

Router::add(
    "GET",
    "/api/user/security/2fa",
    fn() => PrivacyController::get2fa(),
    true
);

Router::add(
    "POST",
    "/api/user/security/2fa",
    fn() => PrivacyController::update2fa(),
    true
);

Router::add(
    "GET",
    "/api/user/account-health",
    fn() => UserController::getAccountHealth(),
    true
);

Router::add(
    "GET",
    "/api/user/login-activity",
    fn() => AuthController::getLoginActivity(),
    true
);

Router::add(
    "GET",
    "/api/user/get-devices",
    fn() => AuthController::getLoggedInDevices(),
    true
);

Router::add(
    "POST",
    "/api/user/logout-all",
    fn() => AuthController::logoutAllDevices(),
    true,
);

Router::add(
    "GET",
    "/api/get-notification-count",
    fn() => NotificationController::getNotificationCount(),
    true
);

Router::add(
    "GET",
    "/api/get-unread-message-count",
    fn() => ChatController::getUnreadMessageCount(),
    true
);

Router::add(
    "GET",
    "/api/get-blocked-users",
    fn() => FriendController::getBlockedUsers(),
    true
);