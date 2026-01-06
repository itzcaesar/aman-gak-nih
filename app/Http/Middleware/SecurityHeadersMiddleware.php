<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeadersMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Remove information disclosure headers
        $response->headers->remove('X-Powered-By');

        // Add Security Headers
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

        // Environment Logic
        if (!app()->isLocal()) {
            // PRODUCTION: Strict Security
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

            $csp =
                "default-src 'self'; " .
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com; " .
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " .
                "font-src 'self' https://fonts.gstatic.com; " .
                "img-src 'self' data: https://www.google.com; " .
                "frame-src 'self' https://www.google.com https://challenges.cloudflare.com; " .
                "connect-src 'self' https://www.google-analytics.com;";

            $response->headers->set('Content-Security-Policy', $csp);
        } else {
            // Force clear HSTS cache to prevent HTTPS redirect issues on localhost
            $response->headers->set('Strict-Transport-Security', 'max-age=0');
            // No CSP in local to prevent Vite/Hot-Reload blocking
        }

        return $response;
    }
}
