<?php

namespace App\Services\Analyzers;

use App\Models\Scan;

class UrlHeuristicAnalyzer implements AnalyzerInterface
{
    public function name(): string
    {
        return 'URL Heuristics';
    }

    public function analyze(Scan $scan, array $context = []): array
    {
        $signals = [];
        $url = $scan->normalized_url;
        $parsed = parse_url($url);
        $host = $parsed['host'] ?? '';
        $path = $parsed['path'] ?? '';
        $query = $parsed['query'] ?? '';

        // Whitelist for Heuristics
        // If domain is known good major platform, we skip generic heuristic checks to avoid false positives.
        $whitelist = ['google.com', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'github.com', 'paypal.com'];
        $isWhitelisted = false;
        foreach ($whitelist as $wl) {
            if (str_ends_with($host, $wl)) {
                $isWhitelisted = true;
                break;
            }
        }

        // 1. Keyword Detection within URL
        // Only run if NOT whitelisted
        if (!$isWhitelisted) {
            $suspiciousKeywords = [
                'login',
                'signin',
                'verify',
                'account',
                'secure',
                'bank',
                'update',
                'wallet',
                'auth',
                'confirm',
                'bca',
                'bri',
                'mandiri',
                'tar',
                'dana',
                'support',
                'service',
                'help'
            ];

            $foundKeywords = [];
            foreach ($suspiciousKeywords as $keyword) {
                // Check if keyword is in host or path
                if (stripos($url, $keyword) !== false) {
                    $foundKeywords[] = $keyword;
                }
            }

            if (!empty($foundKeywords)) {
                $signals[] = [
                    'type' => 'suspicious_keyword',
                    'weight' => -10 * count($foundKeywords), // Cumulative penalty
                    'impact' => 'warning',
                    'description' => 'URL mengandung kata kunci mencurigakan: ' . implode(', ', $foundKeywords)
                ];
            }
        }

        // 2. Subdomain Depth
        $parts = explode('.', $host);
        if (count($parts) > 3) {
            $signals[] = [
                'type' => 'deep_subdomain',
                'weight' => -10,
                'impact' => 'warning',
                'description' => 'Menggunakan subdomain yang sangat dalam (' . count($parts) . ' level).'
            ];
        }

        // 3. TLD Check (Basic)
        $riskyTlds = ['.xyz', '.top', '.club', '.info', '.site', '.tk', '.ml', '.ga', '.cf', '.gq'];
        foreach ($riskyTlds as $tld) {
            if (str_ends_with($host, $tld)) {
                $signals[] = [
                    'type' => 'high_risk_tld',
                    'weight' => -20,
                    'impact' => 'negative',
                    'description' => "Menggunakan TLD berisiko tinggi ($tld) yang sering dipakai phishing."
                ];
                break;
            }
        }

        // 4. URL Encoding/Obfuscation Tricks
        if (strpos($url, '@') !== false) {
            $signals[] = [
                'type' => 'url_auth_confusion',
                'weight' => -50,
                'impact' => 'negative',
                'description' => 'URL menggunakan karakter "@" yang bisa mengecoh tujuan sebenarnya.'
            ];
        }

        // 5. Homoglyph / Punycode check (starts with xn--)
        if (str_starts_with($host, 'xn--')) {
            $signals[] = [
                'type' => 'punycode_domain',
                'weight' => -10,
                'impact' => 'warning',
                'description' => 'Nama domain menggunakan Punycode (karakter non-Latin), mungkin teknik homoglyph.'
            ];
        }

        // 6. IP check in host (if missed by normalizer or obfuscated as hex/octal - regex basic check)
        // Normalizer handles standard IP, but maybe some hex tricks. 
        // For MVP, we stick to standard checks.

        return $signals;
    }
}
