<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class BlockBadBotsMiddleware
{
    /**
     * List of bad bot user agents substrings.
     */
    protected array $badBots = [
        'mj12bot',
        'semrush',
        'dotbot',
        'ahrefs',
        'petalbot',
        'bytespider',
        'mauibot',
        'blexbot'
    ];

    public function handle(Request $request, Closure $next): Response
    {
        $userAgent = strtolower($request->header('User-Agent', ''));

        foreach ($this->badBots as $bot) {
            if (str_contains($userAgent, $bot)) {
                return response()->json([
                    'message' => 'Access denied for this User-Agent.'
                ], 403);
            }
        }

        return $next($request);
    }
}
