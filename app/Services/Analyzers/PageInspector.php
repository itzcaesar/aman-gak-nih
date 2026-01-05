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
            // Fetch with standard User-Agent
            /** @var \Illuminate\Http\Client\Response $response */
            $response = Http::timeout(10)
                ->withoutVerifying()
                ->withUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
                ->get($url);

            if ($response->failed()) {
                $signals[] = [
                    'type' => 'page_fetch_failed',
                    'weight' => 0,
                    'impact' => 'info',
                    'description' => 'Gagal mengambil konten halaman: ' . $response->status()
                ];
                return $signals;
            }

            $html = $response->body();

            // Cache HTML for shared usage
            \Illuminate\Support\Facades\Cache::put('scan_html_' . md5($url), $html, 300);

            // Check for Meta Refresh
            if (preg_match('/<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*>/i', $html)) {
                $signals[] = [
                    'type' => 'meta_refresh_detected',
                    'weight' => -10,
                    'impact' => 'warning',
                    'description' => 'Halaman menggunakan Meta Refresh yang mencurigakan untuk pengalihan otomatis.'
                ];
            }

            // Check for hidden iframes
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

            // Check for unencrypted password fields
            if (stripos($html, 'type="password"') !== false && !str_starts_with($url, 'https')) {
                $signals[] = [
                    'type' => 'password_form_insecure',
                    'weight' => -30,
                    'impact' => 'critical',
                    'description' => 'Formulir password ditemukan di halaman tanpa enkripsi (HTTP).'
                ];
            }

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
