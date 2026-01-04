<?php

namespace App\Services\Analyzers;

use App\Models\Scan;
use Illuminate\Support\Facades\Http;

class PageInspector implements AnalyzerInterface
{
    public function name(): string
    {
        return 'Page Content Inspector';
    }

    public function analyze(Scan $scan): array
    {
        $signals = [];
        $url = $scan->normalized_url;

        try {
            // Fetch with a standard User-Agent to avoid blocking
            $response = Http::timeout(10)
                ->withUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
                ->get($url);

            if ($response->failed()) {
                $signals[] = [
                    'type' => 'page_fetch_failed',
                    'weight' => 0, // Neutral, might be offline
                    'impact' => 'info',
                    'description' => 'Gagal mengambil konten halaman: ' . $response->status()
                ];
                return $signals;
            }

            $html = $response->body();

            // Cache HTML for other analyzers (BrandDetector)
            // Use same key strategy
            \Illuminate\Support\Facades\Cache::put('scan_html_' . md5($url), $html, 300);

            // 1. Detect Meta Refresh (often used for sneaky redirects)
            if (preg_match('/<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*>/i', $html)) {
                $signals[] = [
                    'type' => 'meta_refresh_detected',
                    'weight' => -10,
                    'impact' => 'warning',
                    'description' => 'Halaman menggunakan Meta Refresh yang mencurigakan untuk pengalihan otomatis.'
                ];
            }

            // 2. Hidden Iframes (basic check)
            if (
                preg_match('/<iframe[^>]+style=["\']?.*display:\s*none.*["\']?[^>]*>/i', $html) ||
                preg_match('/<iframe[^>]+width=["\']?0["\']?[^>]*>/i', $html)
            ) {
                $signals[] = [
                    'type' => 'hidden_iframe',
                    'weight' => -15,
                    'impact' => 'warning',
                    'description' => 'Terdeteksi iframe tersembunyi yang sering digunakan untuk memuat konten berbahaya.'
                ];
            }

            // 3. Password fields on non-HTTPS (redundant if SslAnalyzer catches, but good specific check)
            if (stripos($html, 'type="password"') !== false && !str_starts_with($url, 'https')) {
                $signals[] = [
                    'type' => 'password_form_insecure',
                    'weight' => -30,
                    'impact' => 'critical',
                    'description' => 'Formulir password ditemukan di halaman tanpa enkripsi (HTTP).'
                ];
            }

            // 4. Title Extraction (for BrandDetector later context, but we can store it or just use it here?)
            // BrandDetector will probably do its own fetch or we should share the response.
            // For MVP simplicity, BrandDetector can run independently or we pass data. 
            // In a cleaner architecture, we'd cache the response.
            // But let's keep robust: BrandDetector will likely try to use the same cached response or fetch again.
            // Given "Async scanning only", separate jobs or cached resource is better. 
            // Let's assume stateless for now.

        } catch (\Exception $e) {
            $signals[] = [
                'type' => 'scan_error',
                'weight' => 0,
                'impact' => 'info',
                'description' => 'Gagal melakukan inspeksi halaman: ' . $e->getMessage()
            ];
        }

        return $signals;
    }
}
