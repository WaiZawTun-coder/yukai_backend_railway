<?php

namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Request;
use App\Core\Response;
use LDAP\Result;


class LoginHistoriesController{

    /* ========== Insert Login Historeis =========== */
    // public static function loginHistories(){
    //     $conn=Database::connect();

    //     $user_id=(int)(Request::input("user_id")?? 0); // logged in user
    //     $device_id=(int)(Request::input("device_id")?? 0);

    //     if($user_id <= 0 || $device_id <= 0){
    //         Response::json([
    //             "status"=>false,
    //             "message"=>"Invalid Input"
    //         ]);
    //         return;
    //     }
    //     // check user exists
    //     $stmt=$conn->prepare("Select * from users where user_id=?");
    //     $stmt->bind_param("i",$user_id);
    //     $stmt->execute();
    //     $result=$stmt->get_result();
    //     if($result->num_rows === 0){
    //         Response::json([
    //             "status"=>false,
    //             "message"=>"User not found"
    //         ]);
    //         return;
    //     }

        // // check device id exists
        // $stmt=$conn->prepare("Select * from devices where id=?");
        // $stmt->bind_param("i",$device_id);
        // $stmt->execute();
        // $result=$stmt->get_result();
        // if($result->num_rows === 0){
        //     Response::json([
        //         "status"=>false,
        //         "message"=>"Device not found"
        //     ]);
        //     return;
        // }

    //     $sql="INSERT INTO login_histories(user_id,id) values (?,?)";
    //     $stmt=$conn->prepare($sql);
    //     $stmt->bind_param("ii",$user_id,$device_id);
    //     $stmt->execute();
    //     Response::json([
    //         "status"=>true,
    //         "message"=>"Insert Successfully"
    //     ]);

    // }

    /* ========== GET Login Historeis =========== */
    public static function getLoginHistories(){
        $conn=Database::connect();
        $user_id=(int)(Request::input("user_id")?? 0);
        $page=isset($_GET['page']) ? max(1, (int) $_GET['page']) :1;
        $limit=5;
        $offset=($page - 1) * $limit;

    
        if($user_id <=0 ){
            Response::json([
                "status"=>false,
                "mesasge"=>"Invalid Input"
            ]);
            return;
        }

        /* ========== Count Total Rows ============== */

        $countStmt=$conn->prepare("SELECT COUNT(*) as total FROM login_histories where user_id=?");
        $countStmt->bind_param("i",$user_id);
        $countStmt->execute();
        $countResult=$countStmt->get_result()->fetch_assoc();

        $totalRecords=(int) $countResult['total'];
        $totalPages=ceil($totalRecords / $limit);

        if($totalRecords === 0){
            Response::json([
                "status"=>false,
                "message"=>"Login Histories not found"
            ]);
            return;
        }

        $stmt=$conn->prepare("SELECT lgh.user_id,lgh.id,lgh.logged_in_time,d.device_id,d.device_name  FROM login_histories lgh INNER JOIN devices d ON lgh.id = d.id WHERE lgh.user_id=?
                 ORDER BY lgh.logged_in_time DESC
                 LIMIT ? OFFSET ? ");

        $stmt->bind_param("iii",$user_id,$limit,$offset);
        $stmt->execute();
        $result = $stmt->get_result();

        $loginHistories =[];
        while($row=$result->fetch_assoc()){
            $loginHistories[]=$row;
        }
        /* ====== RESPONSE ============= */
        Response::json([
            "status"=>true,
            "current_page"=>$page,
            "limit"=>$limit,
            "total_pages"=>$totalPages,
            "total_records"=>$totalRecords,
            "data"=>$loginHistories
        ]);

    }


}