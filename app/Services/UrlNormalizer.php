<?php

namespace App\Services;

class UrlNormalizer
{
    /**
     * Normalize the URL for consistent scanning.
     *
     * @param string $url
     * @return string
     * @throws \InvalidArgumentException
     */
    public function normalize(string $url): string
    {
        $url = trim($url);

        // Basic scheme check
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }

        $parsed = parse_url($url);

        if (!$parsed || !isset($parsed['host'])) {
            throw new \InvalidArgumentException('URL tidak valid.');
        }

        $host = strtolower($parsed['host']);

        // Convert Punycode (IDN) to ASCII for consistent storage
        if (function_exists('idn_to_ascii')) {
            $asciiHost = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($asciiHost !== false) {
                $host = $asciiHost;
            }
        }

        // Reject IP addresses (IPv4)
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            throw new \InvalidArgumentException('Scan IP address tidak didukung via web ini.');
        }

        // Reject localhost/private
        if ($host === 'localhost' || $host === '127.0.0.1' || str_ends_with($host, '.local') || $host === '::1') {
            throw new \InvalidArgumentException('Localhost tidak dapat discan.');
        }

        // Rebuild URL to ensure clean format
        $scheme = isset($parsed['scheme']) ? strtolower($parsed['scheme']) : 'https';
        $path = $parsed['path'] ?? '/';

        // Sanitize query string: strip potentially dangerous params but keep tracking params
        $query = '';
        if (isset($parsed['query'])) {
            // Limit query string length to prevent abuse
            $safeQuery = substr($parsed['query'], 0, 500);
            // Remove any null bytes or control characters
            $safeQuery = preg_replace('/[\x00-\x1F\x7F]/', '', $safeQuery);
            $query = '?' . $safeQuery;
        }

        return "{$scheme}://{$host}{$path}{$query}";
    }
}
