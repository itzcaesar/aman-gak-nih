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
                $harmless = $stats['harmless'] ?? 0;
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
                if ($malicious > 0) {
                    // User Request: > 10 Critical, 5-10 Warning, < 5 Low Risk

                    if ($malicious > 10) {
                        $penalty = 100;
                        $impact = 'critical';
                        $desc = "CRITICAL: Domain flagged by {$malicious} security vendors.";
                    } elseif ($malicious >= 5) {
                        $penalty = min(80, $malicious * 6);
                        $impact = 'warning';
                        $desc = "WARNING: Domain flagged by {$malicious} vendors (Moderate Risk).";
                    } else {
                        // < 5 is considered False Positive / Noise
                        $penalty = 5;
                        $impact = 'info';
                        $desc = "NOTICE: Domain has {$malicious} flags (Likely False Positives).";
                    }

                    // Community Considerations
                    $votes = $data['total_votes'] ?? [];
                    $commBad = $votes['malicious'] ?? 0;
                    $commGood = $votes['harmless'] ?? 0;

                    // Increase penalty if community agrees it's bad
                    if ($commBad > $commGood && $commBad > 5) {
                        $penalty += 10;
                        $desc .= " Community feedback is negative.";
                    }

                    $signal = [
                        'type' => $malicious >= 5 ? 'vt_domain_suspicious' : 'vt_domain_low_risk',
                        'weight' => -$penalty,
                        'impact' => $impact,
                        'description' => $desc,
                        'meta_data' => $deepMeta
                    ];
                } else {
                    // Bonus: High consensus on safety
                    $bonus = ($harmless > 60) ? 10 : 0; // Bonus for very well-known safe sites

                    $signal = [
                        'type' => 'vt_domain_clean',
                        'weight' => 20 + $bonus,
                        'impact' => 'positive',
                        'description' => "Domain is clean on VirusTotal ({$harmless} safe / {$malicious} malicious).",
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

            if ($response instanceof \Exception) {
                \Log::error("VirusTotal API Error (URL): " . $response->getMessage());
                return null;
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

                if ($malicious > 0) {
                    // Dynamic Scoring for URL
                    if ($malicious > 10) {
                        $penalty = 100;
                        $impact = 'critical';
                        $desc = "CRITICAL: URL flagged by {$malicious} security vendors.";
                    } elseif ($malicious >= 5) {
                        $penalty = min(80, $malicious * 6);
                        $impact = 'warning';
                        $desc = "WARNING: URL flagged by {$malicious} vendors (Moderate Risk).";
                    } else {
                        $penalty = 5;
                        $impact = 'info';
                        $desc = "NOTICE: URL has {$malicious} flags (Likely False Positives).";
                    }

                    $type = $malicious >= 5 ? 'vt_url_suspicious' : 'vt_url_low_risk';
                    $weight = -$penalty;
                    $desc = "URL flagged by {$malicious} security vendors.";
                } else {
                    // Clean
                    $type = 'vt_url_clean';
                    $weight = 10;
                    $impact = 'positive';
                    $desc = "URL bersih menurut konsensus vendor.";
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
