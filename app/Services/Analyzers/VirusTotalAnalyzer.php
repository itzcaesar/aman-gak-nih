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
        $host = parse_url($url, PHP_URL_HOST);

        // Check Domain Reputation
        $domainSignal = $this->checkDomain($host, $key);
        if ($domainSignal) {
            $signals[] = $domainSignal;
        }

        // Check URL Specifics
        $urlSignal = $this->checkUrl($url, $key);
        if ($urlSignal) {
            $signals[] = $urlSignal;
        }

        return $signals;
    }

    private function checkDomain(string $domain, string $key): ?array
    {
        $cacheKey = 'vt_domain_' . md5($domain);
        $cached = Cache::get($cacheKey);
        if ($cached)
            return $cached;

        try {
            /** @var \Illuminate\Http\Client\Response $response */
            $response = Http::withHeaders(['x-apikey' => $key])
                ->timeout(10)
                ->get("https://www.virustotal.com/api/v3/domains/{$domain}");

            if ($response->successful()) {
                $data = $response->json()['data']['attributes'] ?? null;
                if (!$data)
                    return null;

                $stats = $data['last_analysis_stats'];
                $malicious = $stats['malicious'] ?? 0;
                $categories = $data['categories'] ?? [];

                $signal = null;
                if ($malicious > 0) {
                    $signal = [
                        'type' => 'vt_domain_malicious',
                        'weight' => -100,
                        'impact' => 'critical',
                        'description' => "Domain ini ({$domain}) ditandai BERBAHAYA oleh {$malicious} vendor keamanan.",
                        'meta_data' => [
                            'source' => 'VirusTotal Domain',
                            'stats' => $stats,
                            'categories' => $categories
                        ]
                    ];
                } elseif (($stats['suspicious'] ?? 0) > 0) {
                    $signal = [
                        'type' => 'vt_domain_suspicious',
                        'weight' => -50,
                        'impact' => 'warning',
                        'description' => "Domain ini ({$domain}) mencurigakan.",
                        'meta_data' => [
                            'source' => 'VirusTotal Domain',
                            'stats' => $stats
                        ]
                    ];
                } else {
                    $signal = [
                        'type' => 'vt_domain_clean',
                        'weight' => 20,
                        'impact' => 'positive',
                        'description' => "Reputasi domain bersih di VirusTotal.",
                        'meta_data' => [
                            'source' => 'VirusTotal Domain',
                            'stats' => $stats,
                            'categories' => $categories,
                            'creation_date' => $data['creation_date'] ?? null
                        ]
                    ];
                }

                Cache::put($cacheKey, $signal, 86400); // 24 Hours
                return $signal;
            }
        } catch (\Exception $e) {
            Log::error("VT Domain fail: " . $e->getMessage());
        }
        return null;
    }

    private function checkUrl(string $url, string $key): ?array
    {
        $cacheKey = 'vt_url_' . md5($url);
        $cached = Cache::get($cacheKey);
        if ($cached)
            return $cached;

        try {
            $urlId = rtrim(base64_encode($url), '=');
            /** @var \Illuminate\Http\Client\Response $response */
            $response = Http::withHeaders(['x-apikey' => $key])
                ->timeout(10)
                ->get("https://www.virustotal.com/api/v3/urls/{$urlId}");

            if ($response->successful()) {
                $data = $response->json()['data']['attributes'] ?? null;
                if (!$data)
                    return null;

                $stats = $data['last_analysis_stats'];
                $malicious = $stats['malicious'] ?? 0;
                $results = $data['last_analysis_results'] ?? [];

                $signal = null;
                if ($malicious > 0) {
                    $signal = [
                        'type' => 'vt_url_malicious',
                        'weight' => -100,
                        'impact' => 'critical',
                        'description' => "URL spesifik ini terdeteksi mengandung malware/phishing.",
                        'meta_data' => [
                            'source' => 'VirusTotal URL',
                            'stats' => $stats,
                            'vendors' => $results
                        ]
                    ];
                } elseif (($stats['suspicious'] ?? 0) > 0) {
                    $signal = [
                        'type' => 'vt_url_clean',
                        'weight' => -30,
                        'impact' => 'warning',
                        'description' => "URL spesifik ini ditandai mencurigakan.",
                        'meta_data' => [
                            'source' => 'VirusTotal URL',
                            'stats' => $stats,
                            'vendors' => $results
                        ]
                    ];
                } else {
                    $signal = [
                        'type' => 'vt_url_clean',
                        'weight' => 10,
                        'impact' => 'positive',
                        'description' => "URL bersih dari malware.",
                        'meta_data' => [
                            'source' => 'VirusTotal URL',
                            'stats' => $stats,
                            'vendors' => $results
                        ]
                    ];
                }

                Cache::put($cacheKey, $signal, 43200);
                return $signal;
            }
        } catch (\Exception $e) {
            Log::error("VT URL fail: " . $e->getMessage());
        }
        return null;
    }
}
