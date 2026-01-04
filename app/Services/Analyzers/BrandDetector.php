<?php

namespace App\Services\Analyzers;

use App\Models\Scan;
use App\Models\BrandFingerprint;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;

class BrandDetector implements AnalyzerInterface
{
    public function name(): string
    {
        return 'Brand Impersonation Detector';
    }

    public function analyze(Scan $scan): array
    {
        $signals = [];
        $url = $scan->normalized_url;
        $host = parse_url($url, PHP_URL_HOST);

        // Fetch HTML (cached if possible from PageInspector, or fresh)
        // Key idea: PageInspector runs before, or we share cache.
        // Let's use a cache key convention based on URL
        $cacheKey = 'scan_html_' . md5($url);
        $html = Cache::get($cacheKey);

        if (!$html) {
            try {
                $response = Http::timeout(5)->get($url);
                if ($response->successful()) {
                    $html = $response->body();
                    // Cache for 5 mins
                    Cache::put($cacheKey, $html, 300);
                }
            } catch (\Exception $e) {
                // Ignore download errors here, PageInspector handles it
            }
        }

        if (!$html) {
            return []; // Cannot analyze without content
        }

        // Extract Title
        $title = '';
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $html, $matches)) {
            $title = trim($matches[1]);
        }

        // Compare against Brand Fingerprints
        $fingerprints = BrandFingerprint::all();

        foreach ($fingerprints as $brand) {
            // If the current domain IS the official domain (or subdomain), skip
            // Allow subdomains of official domain
            if (str_ends_with($host, $brand->domain) || $host === $brand->domain) {
                continue; // It's legitimate
            }

            // Check if Title contains Brand Name
            if ($title && stripos($title, $brand->brand_name) !== false) {
                $signals[] = [
                    'type' => 'brand_impersonation_title',
                    'weight' => -40,
                    'impact' => 'critical',
                    'description' => "Terdeteksi potensi penimuan merek {$brand->brand_name} pada judul halaman, tetapi bukan domain resmi."
                ];
            }

            // Check if URL contains Brand Name (heuristic overlap)
            // e.g. secure-bca-verify.com
            // Don't flag if it's just a general word, but for MVP brands (BCA, BRI, Google, Facebook) it's usually valid.
            if (stripos($url, $brand->brand_name) !== false) {
                $signals[] = [
                    'type' => 'brand_impersonation_url',
                    'weight' => -30,
                    'impact' => 'critical',
                    'description' => "URL mengandung nama merek {$brand->brand_name} tetapi bukan domain resmi."
                ];
            }
        }

        return $signals;
    }
}
