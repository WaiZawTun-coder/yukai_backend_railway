<?php
namespace App\Service;

use App\Core\Response;

final class PasswordService
{
    private const OPTIONS = [
        'memory_cost' => 1 << 17,
        'time_cost'   => 4,
        'threads'     => 2,
    ];

    public static function hash(string $password): string
    {
        return password_hash(
            $password,
            PASSWORD_ARGON2ID,
            self::OPTIONS
        );
    }

    public static function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash(
            $hash,
            PASSWORD_ARGON2ID,
            self::OPTIONS
        );
    }
    public static function isStrong(string $password): void{
        if(strlen($password)<8){
            Response::json([
                "status"=>false,
                "message"=>"passwords must be at least 8 characters"
            ]);
            
        }
        if(!preg_match('/[A-Z]/',$password)){
            Response::json([
                "status"=>false,
                "message"=>"Passwords must contain upper case"
            ]);
        }
        if(!preg_match('/[a-z]/',$password)){
            Response::json([
                "status"=>false,
                "message"=>"Passwords must contain lower cases"
            ]);
        }
         if (!preg_match('/\d/', $password)) {
            Response::json([
                "status" => false,
                "message" => "Password must contain a number"
            ], 400);
        }
        if(!preg_match('/[!@#$%^&*()_+]/',$password)){
            Response::json([
                "status"=>false,
                "message"=>"Password must contain special characters"
            ]);
        }
        
    }
}
