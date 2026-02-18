<?php
    $server = $_SERVER['SERVER_NAME'] ?? "localhost";
    if($server == "localhost"){
        return [
            'public' => [
                '/yukai_backend/public/',
                '/yukai_backend/public/auth/login.php',
                '/yukai_backend/public/auth/register.php',
                '/yukai_backend/public/auth/refresh.php'
            ],
        
            'admin' => [
                '/yukai_backend/public/admin.php',
            ],
        ];
    }
return [
    'public' => [
        "/auth/login.php",
        "/auth/register.php"
    ],
    'admin' => [
        "/admin.php"
    ]
];
    