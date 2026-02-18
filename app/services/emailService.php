<?php
namespace App\Service;

use App\Core\Response;

class EmailService{
    public static function validate($email) {
        if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
            Response::json([
                "status"=>false,
                "message"=>"Invalid email format"
            ]);
        }
    }
}