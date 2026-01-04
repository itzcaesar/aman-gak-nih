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
        $query = isset($parsed['query']) ? '?' . $parsed['query'] : '';

        return "{$scheme}://{$host}{$path}{$query}";
    }
}
