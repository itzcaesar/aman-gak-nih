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

    public function analyze(Scan $scan, array $context = []): array
    {
        $signals = [];
        $url = $scan->normalized_url;
        $host = parse_url($url, PHP_URL_HOST);

        // Fetch HTML (cached if possible from PageInspector, or fresh)
        $cacheKey = 'scan_html_' . md5($url);
        $html = Cache::get($cacheKey);

        if (!$html) {
            try {
                /** @var \Illuminate\Http\Client\Response $response */
                $response = Http::timeout(5)->get($url);
                if ($response->successful()) {
                    $html = $response->body();
                    // Cache for 5 mins
                    Cache::put($cacheKey, $html, 300);
                }
            } catch (\Exception $e) {
            }
        }

        if (!$html) {
            return [];
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
            if (str_ends_with($host, $brand->domain) || $host === $brand->domain) {
                continue;
            }

            // Regex for whole word matching to avoid "perdana" matching "dana"
            $brandRegex = "/\b" . preg_quote($brand->brand_name, '/') . "\b/i";

            // Check if Title contains Brand Name
            if ($title && preg_match($brandRegex, $title)) {
                $signals[] = [
                    'type' => 'brand_impersonation_title',
                    'weight' => -40,
                    'impact' => 'critical',
                    'description' => "Terdeteksi potensi penimuan merek {$brand->brand_name} pada judul halaman, tetapi bukan domain resmi."
                ];
            }

            // Check if URL contains Brand Name (heuristic overlap)
            if (preg_match($brandRegex, $url)) {
                $signals[] = [
                    'type' => 'brand_impersonation_url',
                    'weight' => -30,
                    'impact' => 'critical',
                    'description' => "URL mengandung nama merek {$brand->brand_name} (whole word) tetapi bukan domain resmi."
                ];
            }
        }

        return $signals;
    }
}
