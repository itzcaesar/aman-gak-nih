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

    public function getAsyncRequests(Scan $scan): array
    {
        $key = env('VIRUSTOTAL_API_KEY');
        if (empty($key)) {
            return [];
        }

        $url = $scan->normalized_url;
        $host = parse_url($url, PHP_URL_HOST);
        $requests = [];

        // Domain Check
        $domainCacheKey = 'vt_domain_' . md5($host);
        if (!Cache::has($domainCacheKey)) {
            $requests['vt_domain'] = [
                'method' => 'GET',
                'url' => "https://www.virustotal.com/api/v3/domains/{$host}",
                'headers' => ['x-apikey' => $key],
                'options' => ['verify' => false, 'timeout' => 10]
            ];
        }

        // URL Check
        $urlCacheKey = 'vt_url_' . md5($url);
        if (!Cache::has($urlCacheKey)) {
            $urlId = rtrim(base64_encode($url), '=');
            $requests['vt_url'] = [
                'method' => 'GET',
                'url' => "https://www.virustotal.com/api/v3/urls/{$urlId}",
                'headers' => ['x-apikey' => $key],
                'options' => ['verify' => false, 'timeout' => 10]
            ];
        }

        return $requests;
    }

    public function analyze(Scan $scan, array $context = []): array
    {
        $key = env('VIRUSTOTAL_API_KEY');
        if (empty($key)) {
            return [];
        }

        $url = $scan->normalized_url;
        $signals = [];
        $host = parse_url($url, PHP_URL_HOST);

        // Check Domain Reputation
        // Pass context response if available
        $domainResponse = $context['vt_domain'] ?? null;
        $domainSignal = $this->checkDomain($host, $key, $domainResponse);
        if ($domainSignal) {
            $signals[] = $domainSignal;
        }

        // Check URL Specifics
        $urlResponse = $context['vt_url'] ?? null;
        $urlSignal = $this->checkUrl($url, $key, $urlResponse);
        if ($urlSignal) {
            $signals[] = $urlSignal;
        }

        return $signals;
    }

    private function checkDomain(string $domain, string $key, $preFetchedResponse = null): ?array
    {
        $cacheKey = 'vt_domain_' . md5($domain);
        $cached = Cache::get($cacheKey);
        if ($cached)
            return $cached;

        try {
            if ($preFetchedResponse) {
                $response = $preFetchedResponse;
            } else {
                /** @var \Illuminate\Http\Client\Response $response */
                $response = Http::withHeaders(['x-apikey' => $key])
                    ->withoutVerifying()
                    ->timeout(10)
                    ->get("https://www.virustotal.com/api/v3/domains/{$domain}");
            }

            if ($response->successful()) {
                $data = $response->json()['data']['attributes'] ?? null;
                if (!$data)
                    return null;

                $stats = $data['last_analysis_stats'];
                $malicious = $stats['malicious'] ?? 0;
                $categories = $data['categories'] ?? [];

                // Tiered scoring: 1-2 = info, 3-5 = warning, 6+ = critical
                $suspicious = $stats['suspicious'] ?? 0;
                $totalBad = $malicious + $suspicious;

                // Common metadata for all signals
                $deepMeta = [
                    'source' => 'VirusTotal Domain',
                    'stats' => $stats,
                    'categories' => $categories,
                    'creation_date' => $data['creation_date'] ?? null,
                    'last_dns_records' => $data['last_dns_records'] ?? [],
                    'last_https_certificate' => $data['last_https_certificate'] ?? null,
                    'jarm' => $data['jarm'] ?? null,
                    'whois' => $data['whois'] ?? null,
                    'registrar' => $data['registrar'] ?? null,
                    'popularity_ranks' => $data['popularity_ranks'] ?? [],
                    'last_analysis_date' => $data['last_analysis_date'] ?? null,
                    'votes' => $data['total_votes'] ?? [],
                ];

                $signal = null;
                if ($malicious >= 6) {
                    // Confirmed malicious - multiple vendors agree
                    $signal = [
                        'type' => 'vt_domain_malicious',
                        'weight' => -100,
                        'impact' => 'critical',
                        'description' => "Domain ini ({$domain}) TERIDENTIFIKASI BERBAHAYA oleh {$malicious} vendor keamanan.",
                        'meta_data' => $deepMeta
                    ];
                } elseif ($malicious >= 3) {
                    // High suspicion
                    $signal = [
                        'type' => 'vt_domain_suspicious',
                        'weight' => -50,
                        'impact' => 'warning',
                        'description' => "Domain ini ({$domain}) mencurigakan - {$malicious} vendor melaporkan masalah.",
                        'meta_data' => $deepMeta
                    ];
                } elseif ($totalBad > 0) {
                    // Low concern - possibly false positive
                    $signal = [
                        'type' => 'vt_domain_low_risk',
                        'weight' => -10,
                        'impact' => 'info',
                        'description' => "Domain ini ({$domain}) memiliki {$totalBad} laporan minor (kemungkinan false positive).",
                        'meta_data' => $deepMeta
                    ];
                } else {
                    // Clean
                    $signal = [
                        'type' => 'vt_domain_clean',
                        'weight' => 20,
                        'impact' => 'positive',
                        'description' => "Reputasi domain bersih di VirusTotal.",
                        'meta_data' => $deepMeta
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

    private function checkUrl(string $url, string $key, $preFetchedResponse = null): ?array
    {
        $cacheKey = 'vt_url_' . md5($url);
        $cached = Cache::get($cacheKey);
        if ($cached)
            return $cached;

        try {
            if ($preFetchedResponse) {
                $response = $preFetchedResponse;
            } else {
                $urlId = rtrim(base64_encode($url), '=');
                /** @var \Illuminate\Http\Client\Response $response */
                $response = Http::withHeaders(['x-apikey' => $key])
                    ->withoutVerifying()
                    ->timeout(10)
                    ->get("https://www.virustotal.com/api/v3/urls/{$urlId}");
            }

            if ($response->successful()) {
                $data = $response->json()['data']['attributes'] ?? null;
                if (!$data)
                    return null;

                $stats = $data['last_analysis_stats'];
                $malicious = $stats['malicious'] ?? 0;
                $results = $data['last_analysis_results'] ?? [];

                // Tiered URL scoring
                $suspicious = $stats['suspicious'] ?? 0;
                $totalBad = $malicious + $suspicious;

                $type = 'vt_url_clean';
                $weight = 10;
                $impact = 'positive';
                $desc = 'URL bersih dari malware.';

                if ($malicious >= 6) {
                    $type = 'vt_url_malicious';
                    $weight = -100;
                    $impact = 'critical';
                    $desc = "URL ini TERIDENTIFIKASI BERBAHAYA oleh {$malicious} vendor.";
                } elseif ($malicious >= 3) {
                    $type = 'vt_url_suspicious';
                    $weight = -50;
                    $impact = 'warning';
                    $desc = "URL ini mencurigakan - {$malicious} vendor melaporkan masalah.";
                } elseif ($totalBad > 0) {
                    $type = 'vt_url_low_risk';
                    $weight = -10;
                    $impact = 'info';
                    $desc = "URL memiliki {$totalBad} laporan minor (kemungkinan false positive).";
                }

                $signal = [
                    'type' => $type,
                    'weight' => $weight,
                    'impact' => $impact,
                    'description' => $desc,
                    'meta_data' => [
                        'source' => 'VirusTotal URL',
                        'stats' => $stats,
                        'vendors' => $results,
                        'http_response' => [
                            'final_url' => $data['last_final_url'] ?? null,
                            'status_code' => $data['last_http_response_code'] ?? null,
                            'content_length' => $data['last_http_response_content_length'] ?? null,
                            'sha256' => $data['last_http_response_content_sha256'] ?? null,
                            'headers' => $data['last_http_response_headers'] ?? [],
                        ],
                        'html_info' => [
                            'title' => $data['html_meta']['title'][0] ?? null,
                        ],
                        'votes' => $data['total_votes'] ?? [],
                        'submission' => [
                            'date' => $data['last_submission_date'] ?? null,
                        ]
                    ]
                ];

                Cache::put($cacheKey, $signal, 43200);
                return $signal;
            }
        } catch (\Exception $e) {
            Log::error("VT URL fail: " . $e->getMessage());
        }
        return null;
    }
}
