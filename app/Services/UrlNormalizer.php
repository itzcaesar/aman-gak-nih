<?php

namespace App\Services;

class UrlNormalizer
{
    /**
     * Normalize the given URL.
     *
     * @param string $url
     * @return string
     */
    public function normalize(string $url): string
    {
        $url = trim($url);

        // Add scheme if missing
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'http://' . $url;
        }

        // Parse URL
        $parsed = parse_url($url);
        
        if (!isset($parsed['host'])) {
            throw new \InvalidArgumentException("Invalid URL: Host not found");
        }

        // Lowercase host
        $parsed['host'] = strtolower($parsed['host']);

        // Remove www. from host potentially (optional, but good for standardization)
        // $parsed['host'] = preg_replace('/^www\./', '', $parsed['host']);

        // Reconstruct URL
        $scheme = isset($parsed['scheme']) ? $parsed['scheme'] . '://' : 'http://';
        $host = $parsed['host'];
        $port = isset($parsed['port']) ? ':' . $parsed['port'] : '';
        $path = isset($parsed['path']) ? $parsed['path'] : '/';
        $query = isset($parsed['query']) ? '?' . $parsed['query'] : '';
        $fragment = isset($parsed['fragment']) ? '#' . $parsed['fragment'] : '';

        return $scheme . $host . $port . $path . $query . $fragment;
    }
}
