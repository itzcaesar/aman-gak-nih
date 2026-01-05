<?php

namespace App\Services\Analyzers;

use App\Models\Scan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class VirusTotalAnalyzer implements AnalyzerInterface
{
    public function name(): string
    {
        return 'VirusTotal Intelligence';
    }

    public function analyze(Scan $scan): array
    {
        $key = env('VIRUSTOTAL_API_KEY');
        if (empty($key)) {
            return [];
        }

        $url = $scan->normalized_url;
        $signals = [];

        // Cache Key (important for API limits)
        $cacheKey = 'vt_scan_' . md5($url);

        // Try to get from cache first (12 hours cache)
        $cachedResult = Cache::get($cacheKey);

        if ($cachedResult) {
            return $cachedResult;
        }

        try {
            // VirusTotal uses URL identifiers (base64 encoded without padding)
            $urlId = rtrim(base64_encode($url), '=');

            /** @var \Illuminate\Http\Client\Response $response */
            $response = Http::withHeaders([
                'x-apikey' => $key
            ])->timeout(10)->get("https://www.virustotal.com/api/v3/urls/{$urlId}");

            if ($response->successful()) {
                $data = $response->json()['data']['attributes']['last_analysis_stats'] ?? null;

                if ($data) {
                    $malicious = $data['malicious'] ?? 0;
                    $suspicious = $data['suspicious'] ?? 0;
                    $harmless = $data['harmless'] ?? 0;

                    if ($malicious > 0) {
                        $signals[] = [
                            'type' => 'virustotal_malicious',
                            'weight' => -100, // Maximum Penalty
                            'impact' => 'critical',
                            'description' => "Dikonfirmasi BERBAHAYA oleh {$malicious} vendor keamanan di VirusTotal."
                        ];
                    } elseif ($suspicious > 1) {
                        $signals[] = [
                            'type' => 'virustotal_suspicious',
                            'weight' => -40,
                            'impact' => 'warning',
                            'description' => "Ditandai mencurigakan oleh {$suspicious} vendor keamanan di VirusTotal."
                        ];
                    } else {
                        $signals[] = [
                            'type' => 'virustotal_clean',
                            'weight' => 20,
                            'impact' => 'positive',
                            'description' => "Dinyatakan bersih oleh {$harmless} vendor keamanan global (VirusTotal)."
                        ];
                    }

                    // Cache the result signals
                    Cache::put($cacheKey, $signals, 43200); // 12 Hours
                }
            } elseif ($response->status() === 404) {
                // URL not in VT database yet.
                // We could submit it using POST /urls, but for MVP let's just skip to avoid wait times.
                // Or we can return a neutral signal.
            } else {
                Log::warning('VirusTotal API Error: ' . $response->status());
            }

        } catch (\Exception $e) {
            Log::error('VirusTotal Scan Failed: ' . $e->getMessage());
        }

        return $signals;
    }
}
