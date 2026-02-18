<?php

class Router
{
    private static array $routes = [];

    public static function add(
        string $method,
        string $path,
        callable $handler,
        bool $protected = false
    ) {
        self::$routes[] = compact("method", "path", "handler", "protected");
    }

    public static function dispatch()
    {
        header("Content-Type: application/json");

        $method = strtoupper($_SERVER["REQUEST_METHOD"]);
        $uri = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

        $scriptDir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME']));
        if ($scriptDir !== '/' && str_starts_with($uri, $scriptDir)) {
            $uri = substr($uri, strlen($scriptDir));
        }

        if ($uri === '') {
            $uri = '/';
        }

        foreach (self::$routes as $route) {
            $pattern = preg_replace('#\{[\w]+\}#', '([^/]+)', $route['path']);
            $pattern = "#^{$pattern}$#";

            if ($route["method"] === $method && preg_match($pattern, $uri, $matches)) {
                array_shift($matches);

                if ($route['protected']) {
                    route_guard();
                }
                call_user_func_array($route['handler'], $matches);
                return;
            }
        }

        http_response_code(404);
        echo json_encode(["error" => "Route not found"]);
    }
}
